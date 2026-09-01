import os
import sys
import json
import secrets
import logging
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
import boto3
from fastapi import FastAPI, Depends, HTTPException, Header, status
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

# Setup paths for import compatibility
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if os.path.exists(os.path.join(BASE_DIR, "..", "layer")):
    sys.path.append(os.path.join(BASE_DIR, "..", "layer"))
elif os.path.exists(os.path.join(BASE_DIR, "common")):
    sys.path.append(BASE_DIR)

from common import utils

# Setup Logging
logger = logging.getLogger("viewer")
logger.setLevel(os.getenv("LOG_LEVEL", "INFO"))

app = FastAPI(title="Threat Sifter Viewer API")

# Initialize DynamoDB Table
db_manager = utils.DynamoDBManager()
table = db_manager.table

# Authentication helpers
def get_expected_password() -> str:
    expected_password = os.getenv("VIEWER_PASSWORD")
    if not expected_password:
        param_name = os.getenv("VIEWER_PASSWORD_PARAM")
        if param_name:
            expected_password = utils.get_ssm_parameter(param_name)
    if not expected_password:
        expected_password = "admin"  # Default fallback
    return expected_password

def verify_password(x_viewer_password: Optional[str] = Header(None)):
    expected = get_expected_password()
    if not x_viewer_password or x_viewer_password != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect password"
        )
    return True

# Request schemas
class MetadataUpdate(BaseModel):
    is_read: bool
    feedback: str
    feedback_reviewed: bool

class SiteCreate(BaseModel):
    url: str
    name: str
    watcher: str

class ManualSubmit(BaseModel):
    site_id: str
    url: str
    title: str
    summary: Optional[str] = ""
    published_at: Optional[str] = None

# Root Route: Serve single-page dashboard HTML for all main router paths
@app.get("/", response_class=HTMLResponse)
@app.get("/articles", response_class=HTMLResponse)
@app.get("/articles/{article_id}", response_class=HTMLResponse)
@app.get("/quick-view", response_class=HTMLResponse)
@app.get("/site-config", response_class=HTMLResponse)
@app.get("/submit", response_class=HTMLResponse)
@app.get("/stats", response_class=HTMLResponse)
def get_index(article_id: Optional[str] = None):
    html_path = os.path.join(BASE_DIR, "index.html")
    if os.path.exists(html_path):
        with open(html_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>Dashboard template (index.html) not found in container</h1>"

@app.post("/api/verify-auth")
def post_verify_auth(auth = Depends(verify_password)):
    return {"status": "authenticated"}

@app.get("/api/articles")
def get_articles(
    status_filter: str = "All",
    read_filter: str = "All",
    search_query: Optional[str] = None,
    search_field: str = "all",
    exclusive_start_key: Optional[str] = None,
    auth = Depends(verify_password)
):
    if table is None:
        raise HTTPException(status_code=500, detail="DynamoDB Table is not configured.")
    
    try:
        import base64
        
        # If read_filter is Unread only, use UnreadIndex for efficient querying
        if read_filter == "Unread" and status_filter == "All":
            query_kwargs = {
                "IndexName": "UnreadIndex",
                "KeyConditionExpression": boto3.dynamodb.conditions.Key("unread_flag").eq("1"),
                "ScanIndexForward": False,  # Descending (newest first)
                "Limit": 2000  # Get more unread articles at once
            }
        # If search query is present, pull a large slice of records with minimum attributes (Projection)
        # to ensure we search far into the past without fetching heavy JSON metadata payload.
        elif search_query:
            query_kwargs = {
                "IndexName": "TypeIndex",
                "KeyConditionExpression": boto3.dynamodb.conditions.Key("category").eq("Article"),
                "ScanIndexForward": False,
                "Limit": 2000,
                # Project only list view metadata to save read costs & bandwidth
                "ProjectionExpression": "pk, sk, title, article_url, published_at, is_read, feedback, feedback_reviewed, processing_status, summary"
            }
        else:
            query_kwargs = {
                "IndexName": "TypeIndex",
                "KeyConditionExpression": boto3.dynamodb.conditions.Key("category").eq("Article"),
                "ScanIndexForward": False,  # Descending (newest first)
                "Limit": 200
            }
        
        if exclusive_start_key:
            try:
                decoded = base64.b64decode(exclusive_start_key).decode("utf-8")
                query_kwargs["ExclusiveStartKey"] = json.loads(decoded)
            except Exception as e:
                logger.error(f"Failed to decode exclusive_start_key: {e}")

        response = table.query(**query_kwargs)
        items = response.get("Items", [])
        last_key = response.get("LastEvaluatedKey")
        
        encoded_last_key = None
        # Disable pagination token during bulk searches to return matches in one go
        if last_key and not search_query:
            encoded_last_key = base64.b64encode(json.dumps(last_key).encode("utf-8")).decode("utf-8")
        
        filtered = []
        for item in items:
            # Ensure defaults for compatibility
            if "is_read" not in item:
                item["is_read"] = False
            if "feedback" not in item:
                item["feedback"] = ""
            if "feedback_reviewed" not in item:
                item["feedback_reviewed"] = False
                
            # Status filter
            status_val = item.get("processing_status", "UNKNOWN")
            if status_filter != "All" and status_val != status_filter:
                continue
            
            # Read filter
            is_read = item.get("is_read", False)
            if read_filter == "Unread" and is_read:
                continue
            elif read_filter == "Read" and not is_read:
                continue
            
            # Perform Case-Insensitive search locally against retrieved records
            if search_query:
                sq = search_query.lower()
                title_val = item.get("title", "").lower()
                url_val = item.get("article_url", "").lower()
                summary_val = item.get("summary", "").lower()
                
                if search_field == "title":
                    if sq not in title_val:
                        continue
                elif search_field == "url":
                    if sq not in url_val:
                        continue
                elif search_field == "summary":
                    if sq not in summary_val:
                        continue
                else: # "all"
                    if sq not in title_val and sq not in url_val and sq not in summary_val:
                        continue
            
            filtered.append(item)
            
        return {
            "articles": filtered,
            "last_evaluated_key": encoded_last_key
        }
    except Exception as e:
        logger.error(f"Error fetching articles: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/articles/{article_id}")
def get_article(article_id: str, auth = Depends(verify_password)):
    if table is None:
        raise HTTPException(status_code=500, detail="DynamoDB Table is not configured.")
    
    try:
        response = table.query(
            KeyConditionExpression=boto3.dynamodb.conditions.Key("pk").eq(article_id)
        )
        items = response.get("Items", [])
        
        meta = None
        iocs = []
        ioas = []
        malwares = []
        
        for item in items:
            sk = item.get("sk", "")
            if sk == "META":
                meta = item
            elif sk.startswith("IOC#"):
                iocs.append(item)
            elif sk.startswith("IOA#"):
                ioas.append(item)
            elif sk.startswith("MALWARE#"):
                malwares.append(item)
                
        if not meta:
            raise HTTPException(status_code=404, detail="Article metadata not found.")
            
        # Ensure default metadata fields for compatibility
        if "is_read" not in meta:
            meta["is_read"] = False
        if "feedback" not in meta:
            meta["feedback"] = ""
        if "feedback_reviewed" not in meta:
            meta["feedback_reviewed"] = False
            
        return {
            "meta": meta,
            "iocs": iocs,
            "ioas": ioas,
            "malwares": malwares
        }
    except Exception as e:
        logger.error(f"Error fetching article details: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/articles/{article_id}/metadata")
def post_article_metadata(article_id: str, data: MetadataUpdate, auth = Depends(verify_password)):
    if table is None:
        raise HTTPException(status_code=500, detail="DynamoDB Table is not configured.")
    
    try:
        # Build update expression based on is_read status
        if data.is_read:
            # Mark as read: remove unread_flag
            update_expr = "SET is_read = :r, feedback = :f, feedback_reviewed = :fr REMOVE unread_flag"
            expr_values = {
                ":r": data.is_read,
                ":f": data.feedback,
                ":fr": data.feedback_reviewed
            }
        else:
            # Mark as unread: add unread_flag
            update_expr = "SET is_read = :r, feedback = :f, feedback_reviewed = :fr, unread_flag = :u"
            expr_values = {
                ":r": data.is_read,
                ":f": data.feedback,
                ":fr": data.feedback_reviewed,
                ":u": "1"
            }

        table.update_item(
            Key={"pk": article_id, "sk": "META"},
            UpdateExpression=update_expr,
            ExpressionAttributeValues=expr_values
        )
        return {"status": "success"}
    except Exception as e:
        logger.error(f"Failed to update metadata: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/sites")
def get_sites(auth = Depends(verify_password)):
    if table is None:
        raise HTTPException(status_code=500, detail="DynamoDB Table is not configured.")
    
    try:
        response = table.query(
            IndexName="TypeIndex",
            KeyConditionExpression=boto3.dynamodb.conditions.Key("category").eq("Site"),
        )
        items = response.get("Items", [])
        if not items:
            response = table.scan(
                FilterExpression=boto3.dynamodb.conditions.Attr("pk").begins_with("site-") & boto3.dynamodb.conditions.Attr("sk").eq("META")
            )
            items = response.get("Items", [])
        return items
    except Exception as e:
        logger.error(f"Error fetching sites: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/sites")
def post_site(data: SiteCreate, auth = Depends(verify_password)):
    if table is None:
        raise HTTPException(status_code=500, detail="DynamoDB Table is not configured.")
    
    try:
        # Check if URL exists
        response = table.scan(
            FilterExpression=boto3.dynamodb.conditions.Attr("site_url").eq(data.url) & boto3.dynamodb.conditions.Attr("sk").eq("META"),
            ProjectionExpression="pk"
        )
        if len(response.get("Items", [])) > 0:
            raise HTTPException(status_code=400, detail="Site URL is already registered.")
            
        site_hex = secrets.token_hex(8)
        site_id = f"site-{site_hex}"
        timestamp = datetime.now().isoformat()
        
        item = {
            "pk": site_id,
            "sk": "META",
            "site_id": site_id,
            "category": "Site",
            "status": "ACTIVE",
            "last_checked_at": "1970-01-01T00:00:00",
            "site_url": data.url,
            "site_name": data.name,
            "watcher": data.watcher or "threat-sifter",
            "created_at": timestamp,
            "published_at": timestamp,
        }
        table.put_item(Item=item)
        return {"status": "success", "site_id": site_id}
    except Exception as e:
        logger.error(f"Failed to create site: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/sites/{site_id}/toggle")
def post_site_toggle(site_id: str, auth = Depends(verify_password)):
    if table is None:
        raise HTTPException(status_code=500, detail="DynamoDB Table is not configured.")
    
    try:
        response = table.get_item(Key={"pk": site_id, "sk": "META"})
        site = response.get("Item")
        if not site:
            raise HTTPException(status_code=404, detail="Site not found.")
            
        curr_status = site.get("status", "ACTIVE")
        new_status = "INACTIVE" if curr_status == "ACTIVE" else "ACTIVE"
        
        table.update_item(
            Key={"pk": site_id, "sk": "META"},
            UpdateExpression="SET #s = :val",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":val": new_status},
        )
        return {"status": "success", "new_status": new_status}
    except Exception as e:
        logger.error(f"Failed to toggle site status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/sites/{site_id}/recrawl")
def post_site_recrawl(site_id: str, auth = Depends(verify_password)):
    if table is None:
        raise HTTPException(status_code=500, detail="DynamoDB Table is not configured.")
    
    try:
        table.update_item(
            Key={"pk": site_id, "sk": "META"},
            UpdateExpression="SET last_checked_at = :t",
            ExpressionAttributeValues={":t": "1970-01-01T00:00:00"},
        )
        return {"status": "success"}
    except Exception as e:
        logger.error(f"Failed to reset last checked: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/sites/{site_id}")
def delete_site_route(site_id: str, auth = Depends(verify_password)):
    if table is None:
        raise HTTPException(status_code=500, detail="DynamoDB Table is not configured.")
    
    try:
        table.delete_item(Key={"pk": site_id, "sk": "META"})
        return {"status": "success"}
    except Exception as e:
        logger.error(f"Failed to delete site: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/manual-submit")
def post_manual_submit(data: ManualSubmit, auth = Depends(verify_password)):
    if table is None:
        raise HTTPException(status_code=500, detail="DynamoDB Table is not configured.")
    
    try:
        response = table.get_item(Key={"pk": data.site_id, "sk": "META"})
        site = response.get("Item")
        if not site:
            raise HTTPException(status_code=404, detail="Selected site not found.")
            
        site_name = site.get("site_name", "")
        queue_url = os.getenv("SQS_QUEUE_URL")
        if not queue_url:
            raise HTTPException(status_code=500, detail="SQS_QUEUE_URL environment variable is not set.")
            
        message = {
            "site_pk": data.site_id,
            "site_name": site_name,
            "article_url": data.url,
            "title": data.title,
            "summary": data.summary or "",
            "published_at": data.published_at or datetime.now().isoformat(),
            "triage_model_id": os.getenv("TRIAGE_MODEL_ID"),
            "analysis_model_id": os.getenv("ANALYZER_MODEL_ID"),
        }
        
        utils.sqs.send_message(QueueUrl=queue_url, MessageBody=json.dumps(message))
        return {"status": "success"}
    except Exception as e:
        logger.error(f"Failed to submit article manually: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/stats")
def get_stats_route(days: int = 7, auth = Depends(verify_password)):
    if table is None:
        raise HTTPException(status_code=500, detail="DynamoDB Table is not configured.")
    
    try:
        since_dt = datetime.now() - timedelta(days=days)
        since_iso = since_dt.isoformat()
        
        query_kwargs = {
            "IndexName": "TypeIndex",
            "KeyConditionExpression": boto3.dynamodb.conditions.Key("category").eq("Article"),
            "FilterExpression": boto3.dynamodb.conditions.Attr("created_at").gte(since_iso),
            "ProjectionExpression": "pk, processing_status, created_at, site_id",
        }
        
        triage_dropped = 0
        analysis_empty = 0
        threat_detected = 0
        unknown = 0
        
        done = False
        start_key = None
        items = []
        
        while not done:
            if start_key:
                query_kwargs["ExclusiveStartKey"] = start_key
                
            response = table.query(**query_kwargs)
            items.extend(response.get("Items", []))
            
            start_key = response.get("LastEvaluatedKey")
            if not start_key:
                done = True
                
        for item in items:
            status_val = item.get("processing_status")
            if status_val == "TRIAGE_DROPPED":
                triage_dropped += 1
            elif status_val == "ANALYSIS_EMPTY":
                analysis_empty += 1
            elif status_val == "THREAT_DETECTED":
                threat_detected += 1
            else:
                unknown += 1
                
        stats_summary = {
            "triage_dropped": triage_dropped,
            "analysis_empty": analysis_empty,
            "threat_detected": threat_detected,
            "unknown": unknown,
            "total": len(items)
        }
        return {"summary": stats_summary, "items": items}
    except Exception as e:
        logger.error(f"Error fetching stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))
