import argparse
import json
import logging
import os
import secrets
import sys
import time
from datetime import datetime, timedelta, timezone

import boto3
from boto3.dynamodb.conditions import Attr, Key
from dotenv import load_dotenv

load_dotenv()

# Configuration
DEFAULT_TABLE = "ThreatSifterTable"

# Setup sys.path to include lambda directories for local execution
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LAMBDA_DIR = os.path.join(BASE_DIR, "lambda")
sys.path.append(os.path.join(LAMBDA_DIR, "layer"))
sys.path.append(os.path.join(LAMBDA_DIR, "crawler"))
sys.path.append(os.path.join(LAMBDA_DIR, "analyzer"))


def get_session(profile=None):
    """Create a boto3 Session."""
    if not profile:
        profile = os.getenv("AWS_PROFILE")
    if profile:
        return boto3.Session(profile_name=profile)
    return boto3.Session()


def get_table(session, args):
    """Get DynamoDB table resource."""
    dynamodb = session.resource("dynamodb")
    table_name = args.table or os.getenv("DYNAMODB_TABLE") or DEFAULT_TABLE
    return dynamodb.Table(table_name)


def _check_site_exists(table, url):
    """Check if site URL already exists in DynamoDB."""
    try:
        kwargs = {
            "FilterExpression": Attr("site_url").eq(url) & Attr("sk").eq("META"),
            "ProjectionExpression": "pk",
        }
        while True:
            response = table.scan(**kwargs)
            if response.get("Items"):
                return True
            last = response.get("LastEvaluatedKey")
            if not last:
                return False
            kwargs["ExclusiveStartKey"] = last
    except Exception as e:
        print(f"Error checking site existence: {e}")
        return False


def _create_site(
    table, site_url, site_name, watcher="threat-sifter", initial_last_checked="1970-01-01T00:00:00"
):
    """Create a new site item in DynamoDB."""
    if _check_site_exists(table, site_url):
        print(f"Site already exists: {site_url}")
        return False

    # New ID Format: site-<16HEX>
    site_hex = secrets.token_hex(8)
    site_id = f"site-{site_hex}"
    timestamp = datetime.now().isoformat()

    print(f"Seeding site: {site_url} ({site_name})")
    print(f"Generated Site ID: {site_id}")

    item = {
        "pk": site_id,
        "sk": "META",
        "site_id": site_id,
        "category": "Site",  # Enable TypeIndex
        "status": "ACTIVE",
        "last_checked_at": initial_last_checked,
        "site_url": site_url,
        "site_name": site_name,
        "watcher": watcher or "threat-sifter",
        "created_at": timestamp,
        "published_at": timestamp,  # Enable TypeIndex sort
    }

    try:
        table.put_item(Item=item)
        print("Successfully inserted site item.")
        return True
    except Exception as e:
        print(f"Error inserting item: {e}")
        return False


def seed_site(args):
    """Seed initial site data."""
    session = get_session(args.profile)
    table = get_table(session, args)
    _create_site(table, args.url, args.name, watcher=args.watcher)


def seed_from_file(args):
    """Seed sites from a JSON file."""
    session = get_session(args.profile)
    table = get_table(session, args)
    file_path = args.file
    days_ago = args.days_ago

    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            sites = json.load(f)

        if not isinstance(sites, list):
            print("Invalid JSON format. Expected a list of sites.")
            return

        print(f"Found {len(sites)} sites in file.")

        # Calculate initial last_checked
        if days_ago is not None and days_ago >= 0:
            initial_last_checked = (
                datetime.now() - timedelta(days=days_ago)
            ).isoformat()
            print(
                f"Using lookback of {days_ago} days. Last checked set to: {initial_last_checked}"
            )
        else:
            # Default to way back
            initial_last_checked = "1970-01-01T00:00:00"

        success_count = 0
        for site in sites:
            url = site.get("url")
            name = site.get("name")
            watcher = site.get("watcher") or args.watcher
            if url and name:
                # Custom _create_site logic here to override last_checked if needed
                # But _create_site is hardcoded to 1970 currently.
                # Let's refactor _create_site slightly or just update item after creation?
                # Best to modify _create_site to take timestamp argument.
                if _create_site(
                    table, url, name, watcher=watcher, initial_last_checked=initial_last_checked
                ):
                    success_count += 1
            else:
                print(f"Skipping invalid entry: {site}")

        print(f"Finished seeding from file. Added {success_count} new sites.")

    except Exception as e:
        print(f"Error reading/processing file {file_path}: {e}")


def list_sites(args):
    """List all registered sites."""
    session = get_session(args.profile)
    table = get_table(session, args)

    try:
        # 1. Try Query on TypeIndex (category='Site')
        print("Fetching sites via TypeIndex (category='Site')...")
        response = table.query(
            IndexName="TypeIndex",
            KeyConditionExpression=Key("category").eq("Site"),
            ScanIndexForward=True,  # List oldest to newest (or as default)
        )
        items = response.get("Items", [])

        if not items:
            print(
                "No sites found via Index (older items might lack 'category'). Falling back to Scan..."
            )
            # 2. Fallback to Scan (Old way)
            response = table.scan(
                FilterExpression=Attr("pk").begins_with("site-") & Attr("sk").eq("META")
            )
            items = response.get("Items", [])

        print(f"Found {len(items)} sites:")
        print("-" * 178)
        print(
            f"{'Site ID':<40} | {'Site Name':<25} | {'URL':<50} | {'Watcher':<15} | {'Status':<8} | {'Last Checked'}"
        )
        print("-" * 178)

        for item in items:
            site_id = item.get("pk", "")
            name = item.get("site_name", "N/A")
            url = item.get("site_url", "N/A")
            watcher = item.get("watcher", "N/A")
            status = item.get("status", "UNKNOWN")
            last_checked = item.get("last_checked_at", "N/A")
            print(
                f"{site_id:<40} | {name:<25} | {url:<50} | {watcher:<15} | {status:<8} | {last_checked}"
            )
        print("-" * 178)

    except Exception as e:
        print(f"Error listing sites: {e}")


def compare_feeds(args):
    """Compare sites in DynamoDB vs. feeds JSON files."""
    import glob

    feeds_dir = args.feeds_dir or os.path.join(os.path.dirname(os.path.abspath(__file__)), "feeds")

    # Collect URLs from feeds JSON files
    feeds_urls = {}  # url -> {"name": ..., "file": ...}
    pattern = os.path.join(feeds_dir, "*.json")
    for filepath in sorted(glob.glob(pattern)):
        filename = os.path.basename(filepath)
        try:
            with open(filepath) as f:
                sites = json.load(f)
            for site in sites:
                url = site.get("url", "").rstrip("/")
                if url:
                    feeds_urls[url] = {"name": site.get("name", ""), "file": filename}
        except Exception as e:
            print(f"Warning: could not read {filepath}: {e}")

    # Collect URLs from DynamoDB
    session = get_session(args.profile)
    table = get_table(session, args)
    try:
        response = table.query(
            IndexName="TypeIndex",
            KeyConditionExpression=Key("category").eq("Site"),
        )
        db_items = response.get("Items", [])
        if not db_items:
            response = table.scan(
                FilterExpression=Attr("pk").begins_with("site-") & Attr("sk").eq("META")
            )
            db_items = response.get("Items", [])
    except Exception as e:
        print(f"Error fetching from DynamoDB: {e}")
        return

    db_urls = {}  # url -> {"name": ..., "id": ...}
    for item in db_items:
        url = item.get("site_url", "").rstrip("/")
        if url:
            db_urls[url] = {"name": item.get("site_name", ""), "id": item.get("pk", "")}

    feeds_set = set(feeds_urls)
    db_set = set(db_urls)

    only_in_feeds = feeds_set - db_set
    only_in_db = db_set - feeds_set
    in_both = feeds_set & db_set

    print(f"\nfeeds dir : {feeds_dir}")
    print(f"feeds total: {len(feeds_set)}  /  DynamoDB total: {len(db_set)}")
    print("=" * 80)

    if only_in_feeds:
        print(f"\n[feeds only — NOT in DynamoDB] ({len(only_in_feeds)} sites)")
        print("-" * 80)
        for url in sorted(only_in_feeds):
            info = feeds_urls[url]
            print(f"  [{info['file']}] {info['name']}")
            print(f"    {url}")
    else:
        print("\n[feeds only] none")

    if only_in_db:
        print(f"\n[DynamoDB only — NOT in feeds] ({len(only_in_db)} sites)")
        print("-" * 80)
        for url in sorted(only_in_db):
            info = db_urls[url]
            print(f"  [{info['id']}] {info['name']}")
            print(f"    {url}")
    else:
        print("\n[DynamoDB only] none")

    print(f"\n[both] {len(in_both)} sites in common")
    print("=" * 80)


def delete_site(args):
    """Delete a site by ID."""
    session = get_session(args.profile)
    table = get_table(session, args)
    site_id = args.id
    # Expect full ID e.g. "site-..."
    if not site_id.startswith("site-"):
        print("Warning: Site ID should usually start with 'site-'.")

    try:
        table.delete_item(Key={"pk": site_id, "sk": "META"})
        print(f"Successfully deleted site: {site_id}")
    except Exception as e:
        print(f"Error deleting site: {e}")


def toggle_site_active(args):
    """Toggle site active status (ACTIVE <-> INACTIVE)."""
    session = get_session(args.profile)
    table = get_table(session, args)
    site_id = args.id

    try:
        response = table.get_item(Key={"pk": site_id, "sk": "META"})
        if "Item" not in response:
            print(f"Site ID {site_id} not found.")
            return

        item = response["Item"]
        current_status = item.get("status", "ACTIVE")
        new_status = "INACTIVE" if current_status == "ACTIVE" else "ACTIVE"

        table.update_item(
            Key={"pk": site_id, "sk": "META"},
            UpdateExpression="SET #s = :val",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":val": new_status},
        )
        print(f"Site {site_id} status changed: {current_status} -> {new_status}")

    except Exception as e:
        print(f"Error toggling site status: {e}")


def set_site_last_checked(args):
    """Set last_checked_at for a site."""
    session = get_session(args.profile)
    table = get_table(session, args)
    site_id = args.id
    time_str = args.time

    if time_str.lower() == "epoch":
        new_time = "1970-01-01T00:00:00"
    else:
        try:
            datetime.fromisoformat(time_str)
            new_time = time_str
        except ValueError:
            print("Invalid time format. Use ISO 8601 or 'epoch'.")
            return

    try:
        # Update last_checked_at. StatusIndex updates automatically.
        table.update_item(
            Key={"pk": site_id, "sk": "META"},
            UpdateExpression="SET last_checked_at = :t",
            ExpressionAttributeValues={":t": new_time},
        )
        print(f"Site {site_id} last_checked_at set to: {new_time}")

    except Exception as e:
        print(f"Error setting last_checked_at: {e}")


def seed_dummy(args):
    """Seed dummy IoC/IoA/Malware data using new schema."""
    session = get_session(args.profile)
    table = get_table(session, args)

    print("Seeding dummy Threat Intelligence data...")

    # Article
    art_hex = secrets.token_hex(8)
    article_id = f"article-{art_hex}"
    timestamp = datetime.now().isoformat()

    items = []

    # 1. Dummy Article
    items.append(
        {
            "pk": article_id,
            "sk": "META",
            "article_id": article_id,
            "site_id": "site-DUMMY",
            "title": "Dummy Threat Report",
            "article_url": "http://example.com/threat-report",
            "summary": "This is a dummy record for local testing.",
            "published_at": timestamp,
            "triage_result": "{}",
            "analysis_result": "{}",
        }
    )

    # 2. Dummy IoC
    ioc_hex = secrets.token_hex(8)
    items.append(
        {
            "pk": article_id,
            "sk": f"IOC#{ioc_hex}",
            "category": "IoC",
            "published_at": timestamp,
            "indicator": "192.168.1.100",  # Unique query value
            "type": "IP",
            "value": "192.168.1.100",
            "context": "C2 Server",
        }
    )

    # 3. Dummy IoA
    ioa_hex = secrets.token_hex(8)
    items.append(
        {
            "pk": article_id,
            "sk": f"IOA#{ioa_hex}",
            "category": "IoA",
            "published_at": timestamp,
            "indicator": "powershell_hidden",  # Token/Searchable
            "type": "Command",
            "value": "powershell -w hidden -enc",
            "description": "Hidden powershell execution",
        }
    )

    # 4. Dummy Malware
    mal_hex = secrets.token_hex(8)
    items.append(
        {
            "pk": article_id,
            "sk": f"MALWARE#{mal_hex}",
            "category": "MalBehavior",
            "published_at": timestamp,
            "indicator": "Emotet",
            "malware_name": "Emotet",
            "behavior": "Downloads additional payloads",
        }
    )

    try:
        with table.batch_writer() as batch:
            for item in items:
                batch.put_item(Item=item)
        print(f"Successfully inserted dummy items under {article_id}")
    except Exception as e:
        print(f"Error inserting dummy data: {e}")


# === Phase 3: Data Access Commands ===


def list_articles(args):
    """List recent articles (Query TypeIndex or SiteIndex, fallback to Scan)."""
    session = get_session(args.profile)
    table = get_table(session, args)
    site_id = getattr(args, "site_id", None)

    try:
        if site_id:
            print(f"Fetching articles for site '{site_id}' via SiteIndex...")
            response = table.query(
                IndexName="SiteIndex",
                KeyConditionExpression=Key("site_id").eq(site_id),
                ScanIndexForward=False,  # Descending (Newest first)
                Limit=50,
            )
            items = response.get("Items", [])
        else:
            # 1. Try Query on TypeIndex (category='Article')
            print("Fetching recent articles via TypeIndex (category='Article')...")
            response = table.query(
                IndexName="TypeIndex",
                KeyConditionExpression=Key("category").eq("Article"),
                ScanIndexForward=False,  # Descending (Newest first)
                Limit=50,
            )
            items = response.get("Items", [])

            if not items:
                print(
                    "No articles found via Index (older items might lack 'category'). Falling back to Scan..."
                )
                # 2. Fallback to Scan (Old way)
                response = table.scan(
                    FilterExpression=Attr("pk").begins_with("article-")
                    & Attr("sk").eq("META")
                )
                items = response.get("Items", [])
                items.sort(key=lambda x: x.get("published_at", ""), reverse=True)
                items = items[:50]

        print(f"Found {len(items)} articles (showing top 50):")
        print("-" * 80)
        print(f"{'Published':<20} | {'Title':<40} | {'ID'}")
        print("-" * 80)
        for item in items:
            pub = item.get("published_at", "N/A")
            title = item.get("title", "No Title")[:38]
            art_id = item.get("pk")
            print(f"{pub:<20} | {title:<40} | {art_id}")

    except Exception as e:
        print(f"Error listing articles: {e}")


def get_article_detail(args):
    """Get article details by URL."""
    session = get_session(args.profile)
    table = get_table(session, args)
    url = args.url

    try:
        response = table.scan(
            FilterExpression=Attr("article_url").eq(url) & Attr("sk").eq("META")
        )
        items = response.get("Items", [])
        if not items:
            print("Article not found.")
            return

        article = items[0]
        pk = article["pk"]

        # Query items with same PK
        response = table.query(KeyConditionExpression=Key("pk").eq(pk))
        details = response.get("Items", [])

        print("=" * 60)
        print(f"Title: {article.get('title')}")
        print(f"URL: {article.get('article_url')}")
        print("-" * 60)

        # Categorize
        iocs = [i for i in details if i.get("category") == "IoC"]
        ioas = [i for i in details if i.get("category") == "IoA"]
        malware = [i for i in details if i.get("category") == "MalBehavior"]

        if iocs:
            print("\n[IoCs]")
            for i in iocs:
                print(f" - [{i.get('type')}] {i.get('value')} ({i.get('context', '')})")
        if ioas:
            print("\n[IoAs]")
            for i in ioas:
                print(
                    f" - [{i.get('type')}] {i.get('value')} \n   Desc: {i.get('description', '')}"
                )
        if malware:
            print("\n[Malware Behavior]")
            for m in malware:
                print(f" - [{m.get('malware_name')}] {m.get('behavior', '')}")

    except Exception as e:
        print(f"Error getting article details: {e}")


def list_threat_info(args, threat_type):
    """List recent threat info using TypeIndex."""
    session = get_session(args.profile)
    table = get_table(session, args)

    category_map = {
        "ioc": "IoC",
        "ioa": "IoA",
        "malware": "MalBehavior",
    }
    category = category_map.get(threat_type)

    try:
        response = table.query(
            IndexName="TypeIndex",
            KeyConditionExpression=Key("category").eq(category),
            ScanIndexForward=False,  # Descending
            Limit=50,
        )
        items = response.get("Items", [])

        print(f"--- Recent {category} List ({len(items)}) ---")
        for item in items:
            date = item.get("published_at", "")
            if category == "IoC":
                print(f"[{date}] {item.get('type')}: {item.get('value')}")
            elif category == "IoA":
                print(f"[{date}] {item.get('type')}: {item.get('value')}")
            elif category == "MalBehavior":
                print(f"[{date}] {item.get('malware_name')}: {item.get('behavior')}")

    except Exception as e:
        print(f"Error listing {threat_type}: {e}")


def search_threats(args):
    """Search for threat info by value using IndicatorIndex or Scan."""
    session = get_session(args.profile)
    table = get_table(session, args)
    keyword = args.value

    print(f"Searching for '{keyword}'...")

    # 1. Try IndicatorIndex query (exact match for IOC/Malware)
    try:
        response = table.query(
            IndexName="IndicatorIndex",
            KeyConditionExpression=Key("indicator").eq(keyword),
        )
        items = response.get("Items", [])
        if items:
            print(f"Found {len(items)} exact matches via Index:")
            for item in items:
                print(
                    f" - [{item.get('category')}] {item.get('value') or item.get('malware_name')} (in {item.get('pk')})"
                )
            return
    except Exception as e:
        print(f"Index query failed: {e}")

    # 2. Fallback to Scan for partial match
    print("No exact index match. Falling back to Scan...")
    try:
        response = table.scan()
        items = response.get("Items", [])
        results = []
        for item in items:
            # Check all string values
            if any(keyword in str(v) for v in item.values()):
                results.append(item)

        print(f"Scan found {len(results)} matches:")
        for r in results:
            print(f" - [{r.get('sk')}] in {r.get('pk')}")

    except Exception as e:
        print(f"Error searching: {e}")


def stats_report(args):
    """Generate stats report using DynamoDB Scan."""
    session = get_session(args.profile)
    table = get_table(session, args)

    days = args.days or 7
    now_utc = datetime.now(timezone.utc)
    # Start of day `days` ago UTC (e.g. at 00:00:00 UTC)
    since_dt = (now_utc - timedelta(days=days - 1)).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    since_iso = since_dt.strftime("%Y-%m-%dT00:00:00")

    print(
        f"Generating stats for past {days} days (from {since_dt.strftime('%Y-%m-%d')} UTC) from DynamoDB..."
    )

    try:
        print("Scanning TypeIndex (category='Article') for stats...")
        query_kwargs = {
            "IndexName": "TypeIndex",
            "KeyConditionExpression": Key("category").eq("Article"),
            "FilterExpression": Attr("created_at").gte(since_iso),
            "ProjectionExpression": "pk, processing_status, created_at, triage_result, site_id",
        }

        from collections import defaultdict

        daily_counts = defaultdict(
            lambda: {
                "triage_dropped": 0,
                "analysis_empty": 0,
                "threat_detected": 0,
                "unknown": 0,
                "total": 0,
            }
        )

        done = False
        start_key = None

        print("Querying table (this may take a while)...")

        while not done:
            if start_key:
                query_kwargs["ExclusiveStartKey"] = start_key

            response = table.query(**query_kwargs)
            items = response.get("Items", [])

            for item in items:
                ca = item.get("created_at")
                if not ca:
                    continue
                # Extract UTC date (YYYY-MM-DD)
                date_str = ca[:10]
                status = item.get("processing_status")

                daily_counts[date_str]["total"] += 1
                if status == "TRIAGE_DROPPED":
                    daily_counts[date_str]["triage_dropped"] += 1
                elif status == "ANALYSIS_EMPTY":
                    daily_counts[date_str]["analysis_empty"] += 1
                elif status == "THREAT_DETECTED":
                    daily_counts[date_str]["threat_detected"] += 1
                else:
                    daily_counts[date_str]["unknown"] += 1

            start_key = response.get("LastEvaluatedKey")
            if not start_key:
                done = True

        # Prepare dates list for the last N days
        date_list = [
            (since_dt + timedelta(days=i)).strftime("%Y-%m-%d") for i in range(days)
        ]

        print("\n" + "=" * 70)
        print(f"Daily Article Processing Report (Past {days} Days, UTC)")
        print("=" * 70)
        print(
            f"{'Date (UTC)':<12} | {'Triage (Dropped)':<18} | {'Detailed Analysis':<18} | {'Total':<8}"
        )
        print("-" * 70)

        tot_triage = 0
        tot_analysis = 0
        tot_all = 0

        for d in date_list:
            counts = daily_counts[d]
            triage = counts["triage_dropped"]
            # Detailed analysis includes ANALYSIS_EMPTY and THREAT_DETECTED
            analysis = counts["analysis_empty"] + counts["threat_detected"] + counts["unknown"]
            total = counts["total"]

            tot_triage += triage
            tot_analysis += analysis
            tot_all += total

            print(
                f"{d:<12} | {triage:<18} | {analysis:<18} | {total:<8}"
            )

        print("-" * 70)
        print(
            f"{'Total':<12} | {tot_triage:<18} | {tot_analysis:<18} | {tot_all:<8}"
        )
        print("=" * 70)
        print(
            "Note: 'Detailed Analysis' consists of items that passed triage (Threat Detected / Analysis Empty)."
        )

    except Exception as e:
        print(f"Error generating stats: {e}")


def submit_article(args):
    """Manually submit an article to SQS for analysis."""
    session = get_session(args.profile)
    table = get_table(session, args)

    queue_url = args.queue_url or os.getenv("SQS_QUEUE_URL")
    if not queue_url:
        print("ERROR: SQS Queue URL is required. Use --queue-url or set SQS_QUEUE_URL.")
        return

    site_id = args.site_id
    article_url = args.url
    title = args.title
    summary = args.summary or ""
    published_at = args.published_at or datetime.now().isoformat()

    # Fetch site metadata
    try:
        response = table.get_item(Key={"pk": site_id, "sk": "META"})
        site = response.get("Item")
        if not site:
            print(f"ERROR: Site not found: {site_id}")
            return
    except Exception as e:
        print(f"ERROR: Failed to fetch site: {e}")
        return

    site_name = site.get("site_name", "")

    # Duplicate check
    from boto3.dynamodb.conditions import Key as DKey
    try:
        existing_response = table.query(
            IndexName="SiteIndex",
            KeyConditionExpression=DKey("site_id").eq(site_id),
            ScanIndexForward=False,
            Limit=200,
        )
        existing_urls = {item.get("article_url") for item in existing_response.get("Items", [])}
        if article_url in existing_urls:
            print(f"SKIP: Article already exists in DB: {article_url}")
            return
    except Exception as e:
        print(f"WARNING: Could not check for duplicates: {e}")

    # Send to SQS
    message = {
        "site_pk": site_id,
        "site_name": site_name,
        "article_url": article_url,
        "title": title,
        "summary": summary,
        "published_at": published_at,
        "triage_model_id": os.getenv("TRIAGE_MODEL_ID"),
        "analysis_model_id": os.getenv("ANALYZER_MODEL_ID"),
    }

    sqs_client = session.client("sqs")
    try:
        sqs_client.send_message(QueueUrl=queue_url, MessageBody=json.dumps(message))
        print(f"Submitted: {title}")
        print(f"  URL     : {article_url}")
        print(f"  Site    : {site_name} ({site_id})")
        print(f"  Published: {published_at}")
    except Exception as e:
        print(f"ERROR: Failed to send SQS message: {e}")
        return

    # Update last_checked_at if published_at is newer
    last_checked = site.get("last_checked_at", "1970-01-01T00:00:00")
    if published_at > last_checked:
        try:
            table.update_item(
                Key={"pk": site_id, "sk": "META"},
                UpdateExpression="SET last_checked_at = :t",
                ExpressionAttributeValues={":t": published_at},
            )
            print(f"  Updated last_checked_at: {published_at}")
        except Exception as e:
            print(f"WARNING: Failed to update last_checked_at: {e}")


def run_crawler_local(args):
    """Run crawler locally."""
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        stream=sys.stdout,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Ensure DYNAMODB_TABLE is set
    if not os.getenv("DYNAMODB_TABLE"):
        os.environ["DYNAMODB_TABLE"] = DEFAULT_TABLE

    # Ensure SQS_QUEUE_URL is set from args or env
    if args.queue_url:
        os.environ["SQS_QUEUE_URL"] = args.queue_url

    if not os.getenv("SQS_QUEUE_URL"):
        print("WARNING: SQS_QUEUE_URL not set. SQS messages will fail to send.")

    # pylint: disable=import-outside-toplevel
    # 'lambda' is a keyword, so we cannot do 'from lambda.crawler ...' directly in Python < 3.9 (or generally bad practice)
    # But wait, 'lambda' as a directory name is valid on FS but invalid as package name in import statement.
    # We added paths to sys.path, so we should import directly from submodules if possible.
    # We added: sys.path.append(os.path.join(LAMBDA_DIR, "crawler"))
    # So we can import 'crawler_handler' directly.
    import crawler_handler

    # Set model environment variables if provided
    if args.triage_model:
        os.environ["TRIAGE_MODEL_ID"] = args.triage_model
    if args.analysis_model:
        os.environ["ANALYZER_MODEL_ID"] = args.analysis_model

    print("Running Crawler Locally...")
    # Mock event/context
    event = {}
    context = {}
    crawler_handler.lambda_handler(event, context)


def run_analyzer_local(args):
    """Run analyzer locally."""
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        stream=sys.stdout,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Ensure DYNAMODB_TABLE is set
    if not os.getenv("DYNAMODB_TABLE"):
        os.environ["DYNAMODB_TABLE"] = DEFAULT_TABLE

    # pylint: disable=import-outside-toplevel
    # Similarly, added sys.path for analyzer
    import analyzer_handler

    print("Running Analyzer Locally...")
    event = {}
    if args.event:
        with open(args.event, "r", encoding="utf-8") as f:
            event = json.load(f)

    # If no event provided, we might want to scan SQS or just return?
    # For local testing, usually we pass a specific event (simulating SQS message).
    # If empty event, handler might do nothing or fail differently.
    # The handler expects 'Records' with 'body'.
    if not event:
        print("No event provided. Using dummy empty event.")
        event = {"Records": []}

    # Set model environment variables if provided
    if args.triage_model:
        os.environ["TRIAGE_MODEL_ID"] = args.triage_model
    if args.analysis_model:
        os.environ["ANALYZER_MODEL_ID"] = args.analysis_model

    context = {}
    analyzer_handler.lambda_handler(event, context)


def debug_prompt_tuning(args):
    """Debug prompt tuning by running LLM against existing article."""
    session = get_session(args.profile)
    table = get_table(session, args)

    # Imports from layer
    from common import utils

    article_id = args.article_id
    if not article_id.startswith("article-"):
        print("Warning: Article ID usually starts with 'article-'.")

    # 1. Fetch Article Metadata to get URL/Title
    print(f"Fetching article metadata for {article_id}...")
    try:
        response = table.query(KeyConditionExpression=Key("pk").eq(article_id))
        items = response.get("Items", [])
        meta = next((i for i in items if i["sk"] == "META"), None)

        if not meta:
            print(f"Article {article_id} metadata not found.")
            return

        article_url = meta.get("article_url")
        title = meta.get("title")
        print(f"Title: {title}")
        print(f"URL: {article_url}")

    except Exception as e:
        print(f"Error fetching from DynamoDB: {e}")
        return

    # 2. Fetch Content (Fresh)
    print("Fetching article content...")
    content = utils.fetch_article_content(article_url)
    if not content:
        print("Failed to fetch content. Using summary from DB if available.")
        content = meta.get("summary", "")

    if not content:
        print("No content available to analyze.")
        return

    input_text = content  # utils.fetch_article_content returns cleaned text

    # 3. Setup Client
    client = utils.BedrockClient()

    # 4. Handle Config
    if args.lang:
        os.environ["PROMPT_LANG"] = args.lang
        print(f"Language set to: {args.lang}")

    prompt_override = None
    if args.prompt_file:
        if args.type == "all":
            print(
                "Warning: --prompt-file is ignored when --type is 'all'. Using default/loaded prompts."
            )
        else:
            try:
                with open(args.prompt_file, "r", encoding="utf-8") as f:
                    prompt_override = f.read()
                print(f"Loaded prompt override from {args.prompt_file}")
            except Exception as e:
                print(f"Error loading prompt file: {e}")
                return

    # 5. Run LLM
    print("-" * 60)

    # Triage
    if args.type in ["triage", "all"]:
        print("\n--- Running Triage ---")
        triage_prompt = prompt_override if args.type == "triage" else None

        # Construct input context as in handler?
        # Analyzer handler uses: f"Title: {title}\nContent: {input_text}"
        full_input = f"Title: {title}\nContent: {input_text}"

        start = time.time()
        result = client.invoke_triage(full_input, prompt_override=triage_prompt)
        duration = time.time() - start

        print(f"Duration: {duration:.2f}s")
        print(json.dumps(result, indent=2, ensure_ascii=False))

    # Analysis
    if args.type in ["analysis", "all"]:
        print("\n--- Running Analysis ---")
        analysis_prompt = prompt_override if args.type == "analysis" else None

        full_input = f"Title: {title}\nContent: {input_text}"

        start = time.time()
        result = client.invoke_analysis(full_input, prompt_override=analysis_prompt)
        duration = time.time() - start

        print(f"Duration: {duration:.2f}s")
        print(json.dumps(result, indent=2, ensure_ascii=False))

    print("-" * 60)


def inspect_article(args):
    """Inspect article details and associated logs."""
    session = get_session(args.profile)
    table = get_table(session, args)

    article_id = args.article_id
    # Ensure ID starts with 'article-'? Or allow user to pass just the hex?
    # User might copy full ID from list.
    if not article_id.startswith("article-"):
        print("Warning: Article ID usually starts with 'article-'.")

    pk = article_id

    print(f"Inspecting Article: {article_id}")

    try:
        response = table.query(KeyConditionExpression=Key("pk").eq(pk))
        items = response.get("Items", [])
        if not items:
            print("Article not found in DynamoDB.")
            return

        meta = next((i for i in items if i["sk"] == "META"), None)
        if not meta:
            print("Metadata not found.")
            return

        print("-" * 60)
        print(f"Title: {meta.get('title')}")
        print(f"URL: {meta.get('article_url')}")
        print("-" * 60)

        # Show Triage
        print("[Triage Result]")
        print(meta.get("triage_result"))

        # Show Analysis
        print("-" * 60)
        print("[Analysis Result]")
        print(meta.get("analysis_result"))

        # Show Child Items
        print("-" * 60)
        print("[Extracted Items]")
        children = [i for i in items if i["sk"] != "META"]
        for c in children:
            print(f"- [{c.get('category')} / {c.get('sk')}]")
            print(f"  {c}")

    except Exception as e:
        print(f"Error fetching from DynamoDB: {e}")
        return


def compare_triage_models(args):
    """Compare triage results between two Bedrock models."""
    session = get_session(args.profile)
    table = get_table(session, args)
    
    # Override Region for Bedrock
    os.environ["BEDROCK_REGION"] = "ap-northeast-1"
    
    # Import here to avoid early loading if not needed
    import importlib.util
    spec = importlib.util.spec_from_file_location("utils", os.path.join(BASE_DIR, "lambda", "layer", "common", "utils.py"))
    utils = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(utils)
    bedrock = utils.BedrockClient()
    
    limit = args.limit
    nova_model = args.nova_model
    haiku_model = args.haiku_model
    
    print(f"Comparing Triage Models:")
    print(f"  - Haiku Model : {haiku_model}")
    print(f"  - Nova Model  : {nova_model}")
    print(f"  - Limit       : {limit} articles")
    print("-" * 80)
    
    try:
        # Fetch latest articles
        response = table.query(
            IndexName="TypeIndex",
            KeyConditionExpression=Key("category").eq("Article"),
            ScanIndexForward=False,  # Descending (Newest first)
            Limit=limit,
        )
        items = response.get("Items", [])
        
        if not items:
            print("No articles found to compare.")
            return

        total_processed = 0
        haiku_threats = 0
        nova_threats = 0
        diff_count = 0

        for idx, item in enumerate(items):
            title = item.get("title", "No Title")
            url = item.get("article_url", "No URL")
            summary = item.get("summary", "")
            
            print(f"\n[{idx+1}/{len(items)}] Title: {title}")
            print(f"URL: {url}")
            
            # Fetch content or use summary
            # To speed up test or avoid scraping again if not needed, we just use summary if available.
            # But triage normally uses full content if possible.
            # Let's use fetch_article_content from utils, similar to analyzer.
            content = utils.fetch_article_content(url) or summary
            triage_text = f"Title: {title}\nContent: {content}"
            
            print(f"  [Haiku] Running Triage...")
            res_haiku = bedrock.invoke_triage(
                triage_text, model_id=haiku_model, force_ja=args.ja
            )
            
            print(f"  [Nova]  Running Triage...")
            res_nova = bedrock.invoke_triage(
                triage_text, model_id=nova_model, force_ja=args.ja
            )
            
            # Extract results
            h_threat = res_haiku.get("is_threat", "ERROR")
            n_threat = res_nova.get("is_threat", "ERROR")
            
            h_reason = res_haiku.get("reason", "N/A")
            n_reason = res_nova.get("reason", "N/A")
            
            # Compare
            diff_marker = " * DIFF * " if h_threat != n_threat else ""
            
            print(f"  => Result:{diff_marker}")
            print(f"     Haiku: is_threat={h_threat} | reason={h_reason}")
            print(f"     Nova:  is_threat={n_threat} | reason={n_reason}")
            
            # Stats tracking
            total_processed += 1
            if h_threat is True:
                haiku_threats += 1
            if n_threat is True:
                nova_threats += 1
            if h_threat != n_threat:
                diff_count += 1
            
        # Print Stats
        print("\n" + "=" * 80)
        print("Comparison Statistics")
        print("=" * 80)
        print(f"Total Articles Processed : {total_processed}")
        print(f"Haiku Threats Detected   : {haiku_threats}")
        print(f"Nova Threats Detected    : {nova_threats}")
        print(f"Model Differences        : {diff_count}")
        print("=" * 80 + "\n")
            
    except Exception as e:
        print(f"Error during comparison: {e}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Threat Sifter Management Script")
    parser.add_argument("--profile", help="AWS CLI login profile name")
    parser.add_argument("--table", help="DynamoDB Table Name Override")

    # Top-level subparsers for Target (site, dummy, article, ioc, ioa, malware, search)
    subparsers = parser.add_subparsers(
        dest="target", required=True, help="Target resource"
    )

    # === Target: site ===
    site_parser = subparsers.add_parser("site", help="Manage sites")
    site_subparsers = site_parser.add_subparsers(dest="action", required=True)
    site_seed_parser = site_subparsers.add_parser("seed", help="Seed default site")
    site_seed_parser.add_argument(
        "--url", help="URL of the site RSS feed", required=True
    )
    site_seed_parser.add_argument("--name", help="Name of the site", required=True)
    site_seed_parser.add_argument(
        "--watcher", default="threat-sifter", help="Who watches the site (default: threat-sifter)"
    )
    site_seed_parser.set_defaults(func=seed_site)

    site_file_parser = site_subparsers.add_parser(
        "seed-from-file", help="Seed sites from JSON file"
    )
    site_file_parser.add_argument(
        "--file", help="Path to JSON file containing sites", required=True
    )
    site_file_parser.add_argument(
        "--days-ago", type=int, help="Fetch articles from N days ago (default: all)"
    )
    site_file_parser.add_argument(
        "--watcher", default="threat-sifter", help="Default watcher for the sites (default: threat-sifter)"
    )
    site_file_parser.set_defaults(func=seed_from_file)

    site_list_parser = site_subparsers.add_parser("list", help="List all sites")
    site_list_parser.set_defaults(func=list_sites)

    site_compare_parser = site_subparsers.add_parser(
        "compare-feeds", help="Compare DynamoDB sites vs feeds JSON files"
    )
    site_compare_parser.add_argument(
        "--feeds-dir", default=None, help="Path to feeds directory (default: ./feeds)"
    )
    site_compare_parser.set_defaults(func=compare_feeds)

    site_del_parser = site_subparsers.add_parser("delete", help="Delete a site")
    site_del_parser.add_argument("--id", required=True, help="Site ID")
    site_del_parser.set_defaults(func=delete_site)

    site_toggle_parser = site_subparsers.add_parser(
        "toggle-active", help="Toggle site active status"
    )
    site_toggle_parser.add_argument("--id", required=True, help="Site ID")
    site_toggle_parser.set_defaults(func=toggle_site_active)

    site_time_parser = site_subparsers.add_parser(
        "set-last-checked", help="Set site last checked time"
    )
    site_time_parser.add_argument("--id", required=True, help="Site ID")
    site_time_parser.add_argument(
        "--time", required=True, help="ISO format time or 'epoch'"
    )
    site_time_parser.set_defaults(func=set_site_last_checked)

    # === Target: dummy ===
    dummy_parser = subparsers.add_parser("dummy", help="Manage dummy data")
    dummy_subparsers = dummy_parser.add_subparsers(dest="action", required=True)
    dummy_seed_parser = dummy_subparsers.add_parser("seed", help="Seed dummy data")
    dummy_seed_parser.set_defaults(func=seed_dummy)

    # === Target: article ===
    article_parser = subparsers.add_parser("article", help="Manage articles")
    article_subparsers = article_parser.add_subparsers(dest="action", required=True)

    art_list = article_subparsers.add_parser("list", help="List articles")
    art_list.add_argument("--site-id", dest="site_id", help="Filter articles by Site ID (e.g., site-<HEX>)")
    art_list.set_defaults(func=list_articles)

    art_detail = article_subparsers.add_parser("detail", help="Show article detail")
    art_detail.add_argument("--url", required=True, help="Article URL")
    art_detail.set_defaults(func=get_article_detail)

    art_submit = article_subparsers.add_parser(
        "submit", help="Manually submit an article to SQS for analysis"
    )
    art_submit.add_argument("--site-id", required=True, help="Site ID (e.g., site-<HEX>)")
    art_submit.add_argument("--url", required=True, help="Article URL")
    art_submit.add_argument("--title", required=True, help="Article title")
    art_submit.add_argument("--summary", default="", help="Article summary (optional)")
    art_submit.add_argument(
        "--published-at", help="Published datetime in ISO 8601 format (default: now)"
    )
    art_submit.add_argument("--queue-url", help="SQS Queue URL (or set SQS_QUEUE_URL env)")
    art_submit.set_defaults(func=submit_article)

    # === Target: ioc/ioa/malware ===
    for threat in ["ioc", "ioa", "malware"]:
        t_parser = subparsers.add_parser(threat, help=f"Manage {threat}")
        t_subparsers = t_parser.add_subparsers(dest="action", required=True)
        t_list = t_subparsers.add_parser("list", help=f"List recent {threat}")
        t_list.set_defaults(func=lambda a, t=threat: list_threat_info(a, t))

    # === Target: search ===
    # "search" is a target here? Or an action?
    # Request: "IoC、IoA、攻撃者情報を検索するコマンド"
    # Usage: manage.py search --value <val>
    search_parser = subparsers.add_parser("search", help="Search data")
    search_parser.add_argument("--value", required=True, help="Keyword")
    # search doesn't strictly need a sub-action, but argparse subparser usually expects one if built that way?
    # Actually if we define search_parser, we can set default func directly.
    search_parser.set_defaults(func=search_threats)

    # === Target: stats ===
    stats_parser = subparsers.add_parser("stats", help="CloudWatch Logs Statistics")
    stats_parser.add_argument("--days", type=int, default=7, help="Days to look back")
    stats_parser.add_argument("--log-group", help="Log Group Name")
    stats_parser.set_defaults(func=stats_report)

    # === Target: crawler ===
    crawler_parser = subparsers.add_parser("crawler", help="Local Crawler Execution")
    crawler_subparsers = crawler_parser.add_subparsers(dest="action", required=True)
    crawler_run = crawler_subparsers.add_parser("run", help="Run crawler locally")
    crawler_run.add_argument("--queue-url", help="SQS Queue URL")
    crawler_run.add_argument("--triage-model", help="Triage Model ID")
    crawler_run.add_argument("--analysis-model", help="Analysis Model ID")
    crawler_run.set_defaults(func=run_crawler_local)

    # === Target: analyzer ===
    analyzer_parser = subparsers.add_parser("analyzer", help="Local Analyzer Execution")
    analyzer_subparsers = analyzer_parser.add_subparsers(dest="action", required=True)
    analyzer_run = analyzer_subparsers.add_parser("run", help="Run analyzer locally")
    analyzer_run.add_argument("--event", help="Path to event JSON file")
    analyzer_run.add_argument("--triage-model", help="Triage Model ID")
    analyzer_run.add_argument("--analysis-model", help="Analysis Model ID")
    analyzer_run.set_defaults(func=run_analyzer_local)

    # === Target: debug ===
    debug_parser = subparsers.add_parser("debug", help="Debug tools")
    debug_subparsers = debug_parser.add_subparsers(dest="action", required=True)

    debug_inspect = debug_subparsers.add_parser(
        "inspect", help="Inspect article processing"
    )
    debug_inspect.add_argument(
        "--article-id", required=True, help="Article ID (e.g., article-<HEX>)"
    )
    debug_inspect.set_defaults(func=inspect_article)

    debug_compare = debug_subparsers.add_parser(
        "compare-triage", help="Compare triage inference between Haiku and Nova"
    )
    debug_compare.add_argument(
        "--limit", type=int, default=10, help="Number of recent articles to compare"
    )
    debug_compare.add_argument(
        "--nova-model",
        default="jp.amazon.nova-2-lite-v1:0",
        help="Model ID for Nova Lite (Default: jp.amazon.nova-2-lite-v1:0)",
    )
    debug_compare.add_argument(
        "--haiku-model",
        default="jp.anthropic.claude-haiku-4-5-20251001-v1:0",
        help="Model ID for Haiku (Default: jp.anthropic.claude-haiku-4-5-20251001-v1:0)",
    )
    debug_compare.add_argument(
        "--ja",
        action="store_true",
        help="Output the reason in Japanese",
    )
    debug_compare.set_defaults(func=compare_triage_models)
    debug_prompt = debug_subparsers.add_parser(
        "prompt-tuning", help="Tune prompts against existing article"
    )
    # Arguments ordered to show article-id last in help/usage if possible,
    # but argparse help usually follows definition order.
    # User requested article-id at the end for 'sample' usage mostly.
    debug_prompt.add_argument(
        "--type", required=True, choices=["triage", "analysis", "all"], help="Test type"
    )
    debug_prompt.add_argument(
        "--prompt-file", help="Path to custom prompt file (ignored for 'all')"
    )
    debug_prompt.add_argument(
        "--lang", choices=["en", "ja"], help="Language override (en/ja)"
    )
    debug_prompt.add_argument(
        "--article-id", required=True, help="Article ID (e.g., article-<HEX>)"
    )

    debug_prompt.set_defaults(func=debug_prompt_tuning)

    args = parser.parse_args()
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
