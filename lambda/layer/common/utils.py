import json
import logging
import os
import secrets
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, Union

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, ReadTimeoutError

# Logging setup
logger = logging.getLogger()
logger.setLevel(os.getenv("LOG_LEVEL", "INFO"))


def get_session():
    """Create a boto3 Session. Use AWS_PROFILE if set."""
    profile = os.getenv("AWS_PROFILE")
    if profile:
        return boto3.Session(profile_name=profile)
    return boto3.Session()


# Initialize clients lazily or globally using the session helper
session = get_session()
dynamodb = session.resource("dynamodb")
bedrock_runtime = session.client(
    "bedrock-runtime",
    region_name=os.getenv("BEDROCK_REGION", "ap-northeast-1"),
    config=Config(read_timeout=240),
)
sqs = session.client("sqs")

TABLE_NAME = os.getenv("DYNAMODB_TABLE")


class DynamoDBManager:
    """Helper class for DynamoDB Single Table Design operations (Redesigned)."""

    def __init__(self, table_name: str = TABLE_NAME):
        if not table_name:
            logger.warning("DYNAMODB_TABLE environment variable not set.")
            self.table = None
        else:
            self.table = dynamodb.Table(table_name)

    def get_active_sites(self, watcher: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve all active sites using StatusIndex."""
        if not self.table:
            return []
        items = []
        try:
            params = {
                "IndexName": "StatusIndex",
                "KeyConditionExpression": boto3.dynamodb.conditions.Key("status").eq(
                    "ACTIVE"
                ),
            }

            while True:
                response = self.table.query(**params)
                items.extend(response.get("Items", []))

                if "LastEvaluatedKey" in response:
                    params["ExclusiveStartKey"] = response["LastEvaluatedKey"]
                else:
                    break

            if watcher:
                return [
                    item for item in items
                    if item.get("watcher", "threat-sifter") == watcher
                ]
            return items
        except ClientError as e:
            logger.error("Failed to fetch active sites: %s", e)
            raise

    def get_site_article_urls(self, site_pk: str) -> set:
        """Retrieve the most recent 5 article URLs for a specific site."""
        if not self.table:
            return set()
        urls = set()
        try:
            params = {
                "IndexName": "SiteIndex",
                "KeyConditionExpression": boto3.dynamodb.conditions.Key("site_id").eq(site_pk),
                "ScanIndexForward": False,
                "Limit": 100,
            }
            
            response = self.table.query(**params)
            for item in response.get("Items", []):
                url = item.get("article_url")
                if url:
                    urls.add(url)
                    
            return urls
        except ClientError as e:
            logger.error("Failed to fetch article URLs for site %s: %s", site_pk, e)
            return urls


    def update_last_checked(self, site_pk: str, site_sk: str, timestamp: str):
        """Update the last_checked_at timestamp for a site."""
        if not self.table:
            return
        try:
            self.table.update_item(
                Key={"pk": site_pk, "sk": site_sk},
                UpdateExpression="SET last_checked_at = :t",
                ExpressionAttributeValues={
                    ":t": timestamp,
                },
            )
        except ClientError as e:
            logger.error("Failed to update last checked: %s", e)
            raise

    def save_article(self, article_item: Dict[str, Any]):
        """Save an article item."""
        if not self.table:
            return
        try:
            self.table.put_item(Item=article_item)
        except ClientError as e:
            logger.error("Failed to save article: %s", e)
            raise

    def batch_write_items(self, items: List[Dict[str, Any]]):
        """Batch write utility."""
        if not self.table:
            return
        try:
            with self.table.batch_writer() as batch:
                for item in items:
                    batch.put_item(Item=item)
        except ClientError as e:
            logger.error("Failed to batch write: %s", e)
            raise

    def get_site_by_url(self, url: str) -> Optional[Dict[str, Any]]:
        """Helper to find site by URL."""
        # This implementation requires querying or scanning if we don't know the ID.
        # Assuming URL is unique, we might Scan or add a GSI for URL if needed.
        # Currently not strictly required by the plan, but useful for 'seed' check.
        # Since we removed the generic query pattern, scan is safest for now for 'check exists'.
        if not self.table:
            return None
        try:
            response = self.table.scan(
                FilterExpression=boto3.dynamodb.conditions.Attr("site_url").eq(url)
                & boto3.dynamodb.conditions.Attr("sk").eq("META")
            )
            items = response.get("Items", [])
            return items[0] if items else None
        except Exception as e:
            logger.error("Error finding site by URL: %s", e)
            return None


class BedrockClient:
    """Helper for Bedrock model invocations."""

    def _extract_json(self, text: str) -> Dict[str, Any]:
        """Extract JSON from text, handling markdown code blocks and trailing content."""
        text = text.strip()
        if text.startswith("```json"):
            text = text[7:]
        elif text.startswith("```"):
            text = text[3:]

        if text.endswith("```"):
            text = text[:-3]

        text = text.strip()

        # Find the outermost JSON object boundary to strip trailing text
        # (some models append explanatory text after the closing brace)
        start = text.find("{")
        if start != -1:
            depth = 0
            for i, ch in enumerate(text[start:], start):
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        text = text[start : i + 1]
                        break

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # Models sometimes embed raw backslashes in string values (e.g. Windows paths like
            # \\.\pipe\foo). Replace lone backslashes not already part of a valid JSON escape
            # sequence so json.loads can parse them.
            import re as _re
            text = _re.sub(r'\\(?!["\\/bfnrtu])', r'\\\\', text)
            return json.loads(text)

    def _load_prompt(self, prompt_type: str, lang: str = None) -> str:
        """Load prompt from file."""
        if not lang:
            lang = os.getenv("PROMPT_LANG", "ja")

        # Determine path relative to this file
        base_dir = os.path.dirname(os.path.abspath(__file__))
        prompt_path = os.path.join(base_dir, "prompts", lang, f"{prompt_type}.txt")

        try:
            if not os.path.exists(prompt_path):
                logger.warning(
                    "Prompt file not found: %s. Using fallback Japanese prompt.",
                    prompt_path,
                )
                # Fallback to 'ja' if specific lang missing
                prompt_path = os.path.join(
                    base_dir, "prompts", "ja", f"{prompt_type}.txt"
                )

            with open(prompt_path, "r", encoding="utf-8") as f:
                return f.read()
        except Exception as e:
            logger.error("Failed to load prompt from %s: %s", prompt_path, e)
            # Hard fallback if file system fails completely (Keep original as backup string?)
            # Or just raise/return empty to fail fast?
            # Let's re-raise or return a basic hardcoded one to avoid total failure?
            # Returning empty will likely cause downstream LLM confusion.
            return ""

    def invoke_triage(
        self, text: str, model_id: Optional[str] = None, force_ja: bool = False, prompt_override: Optional[str] = None, image_urls: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Invoke LLM for triage."""
        if prompt_override:
            prompt_template = prompt_override
        else:
            prompt_template = self._load_prompt("triage")
        
        lang_instruction = " Please provide the 'reason' in Japanese." if force_ja else ""
        if force_ja and "{{TEXT}}" not in prompt_template:
            # Fallback for very simple prompt override
            prompt_template += lang_instruction + "\n\n{{TEXT}}"

        # Replace placeholder
        prompt = prompt_template.replace("{{TEXT}}", text[:20000])

        if image_urls:
            # Append image URLs for the model to select from
            img_list_str = "\n".join(f"- {url}" for url in image_urls)
            prompt += f"\n\nImage URLs found in article:\n{img_list_str}\n"

        default_model = os.getenv(
            "DEFAULT_TRIAGE_MODEL_ID", "jp.amazon.nova-2-lite-v1:0"
        )
        target_model = model_id or default_model

        if "nova" in target_model.lower():
            # Nova models require a different body format
            body = json.dumps(
                {
                    "inferenceConfig": {"max_new_tokens": 4000},
                    "messages": [{"role": "user", "content": [{"text": prompt}]}],
                }
            )
        else:
            # Claude models
            body = json.dumps(
                {
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 1000,
                    "messages": [{"role": "user", "content": prompt}],
                }
            )

        try:
            response = bedrock_runtime.invoke_model(modelId=target_model, body=body)
            response_body_str = response.get("body").read().decode("utf-8")
            logger.info(
                "Bedrock Triage Response (Model: %s): %s",
                target_model,
                response_body_str,
            )
            response_body = json.loads(response_body_str)

            if "nova" in target_model.lower():
                # Extract for Nova models
                content_text = response_body.get("output", {}).get("message", {}).get("content", [{}])[0].get("text", "")
            else:
                # Extract for Claude models
                content_list = response_body.get("content", [])
                if not content_list:
                    stop_reason = response_body.get("stop_reason", "unknown")
                    logger.warning("Bedrock Triage returned empty content (stop_reason: %s). Treating as non-threat.", stop_reason)
                    return {"is_threat": False, "reason": f"Model refused to respond (stop_reason: {stop_reason})"}
                content_text = content_list[0]["text"]

            return self._extract_json(content_text)
        except ReadTimeoutError as e:
            logger.error("Bedrock Triage timed out (read_timeout exceeded): %s", e)
            raise
        except ClientError as e:
            if e.response["Error"]["Code"] == "ThrottlingException":
                logger.warning("Bedrock Triage Throttled: %s", e)
                raise
            logger.error("Bedrock Triage invocation failed: %s", e)
            return {"is_threat": False, "error": str(e)}
        except Exception as e:
            logger.error("Bedrock Triage invocation failed (Unknown): %s", e)
            return {"is_threat": False, "error": str(e)}

    def invoke_analysis(
        self,
        text: str,
        images: Optional[List[Tuple[str, str]]] = None,
        model_id: Optional[str] = None,
        prompt_override: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Invoke LLM for detail analysis.
        images: List of (base64_data, media_type) tuples
        """
        if prompt_override:
            prompt_template = prompt_override
        else:
            prompt_template = self._load_prompt("analysis")

        # Replace placeholder
        prompt_text = prompt_template.replace("{{TEXT}}", text[:50000])

        default_model = os.getenv(
            "DEFAULT_ANALYSIS_MODEL_ID", "jp.anthropic.claude-sonnet-4-6"
        )
        target_model = model_id or default_model

        # Construct message content
        content_block = []

        # Add images first (getting context from them)
        if images:
            for img_b64, media_type in images:
                content_block.append(
                    {
                        "type": "image",
                        "source": {
                            "type": "base64",
                            "media_type": media_type,
                            "data": img_b64,
                        },
                    }
                )

        # Add text
        content_block.append({"type": "text", "text": prompt_text})

        body = json.dumps(
            {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 8000,
                "temperature": 0,
                "messages": [{"role": "user", "content": content_block}],
            }
        )

        try:
            response = bedrock_runtime.invoke_model(modelId=target_model, body=body)
            response_body_str = response.get("body").read().decode("utf-8")
            logger.info(
                "Bedrock Analysis Response (Model: %s): %s",
                target_model,
                response_body_str,
            )
            response_body = json.loads(response_body_str)
            content_list = response_body.get("content", [])
            if not content_list:
                stop_reason = response_body.get("stop_reason", "unknown")
                logger.warning("Bedrock Analysis returned empty content (stop_reason: %s). Skipping analysis.", stop_reason)
                return {"error": f"Model refused to respond (stop_reason: {stop_reason})", "refusal": True}
            return self._extract_json(content_list[0]["text"])
        except ReadTimeoutError as e:
            logger.error("Bedrock Analysis timed out (read_timeout exceeded): %s", e)
            raise
        except ClientError as e:
            if e.response["Error"]["Code"] == "ThrottlingException":
                logger.warning("Bedrock Analysis Throttled: %s", e)
                raise
            logger.error("Bedrock Analysis invocation failed: %s", e)
            return {"error": str(e)}
        except Exception as e:
            logger.error("Bedrock Analysis invocation failed (Unknown): %s", e)
            return {"error": str(e)}


def get_ssm_parameter(param_name: str) -> Optional[str]:
    """Retrieve parameter from SSM Parameter Store."""
    if not param_name:
        return None

    # session is global
    ssm = session.client("ssm")
    try:
        response = ssm.get_parameter(Name=param_name, WithDecryption=True)
        return response.get("Parameter", {}).get("Value")
    except Exception as e:
        logger.error("Failed to get SSM parameter %s: %s", param_name, e)
        return None


def slack_notify(message: str, token: str) -> None:
    """Send message to Slack."""
    # pylint: disable=import-outside-toplevel
    import requests

    if not token:
        logger.warning("Slack Token not set.")
        return

    url = f"https://hooks.slack.com/services/{token}"
    data = {"text": message}
    headers = {"Content-type": "application/json"}

    try:
        requests.post(url=url, headers=headers, data=json.dumps(data), timeout=10)
    except Exception as e:
        logger.error("Failed to send slack notification: %s", e)


def change_message_visibility(
    queue_url: str, receipt_handle: str, visibility_timeout: int
):
    """Change the visibility timeout of a message."""
    if not queue_url or not receipt_handle:
        return

    try:
        sqs.change_message_visibility(
            QueueUrl=queue_url,
            ReceiptHandle=receipt_handle,
            VisibilityTimeout=visibility_timeout,
        )
        logger.info("Changed visibility timeout to %ds", visibility_timeout)
    except ClientError as e:
        logger.error("Failed to change message visibility: %s", e)


def fetch_article_content(url: str) -> Tuple[Optional[str], List[str]]:
    """
    Fetch and extract main content from a URL.
    Returns (text, image_urls_list)
    """
    # pylint: disable=import-outside-toplevel
    import requests
    from bs4 import BeautifulSoup

    if not url:
        return None, []

    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
        except Exception:
            from curl_cffi import requests as cffi_requests
            response = cffi_requests.get(url, impersonate="chrome", timeout=10)
            response.raise_for_status()

        soup = BeautifulSoup(response.content, "html.parser")

        # Remove script and style elements
        for script in soup(["script", "style", "nav", "footer", "header"]):
            script.extract()

        # Find Images before stripping tags
        images = []
        for img in soup.find_all("img"):
            # Check common lazy loading attributes
            candidates = [
                img.get("src"),
                img.get("data-src"),
                img.get("data-original"),
                img.get("data-url"),
                img.get("data-lazy-src"),
            ]

            final_src = None
            for src in candidates:
                if src and src.startswith("http") and not src.endswith(".svg"):
                    # Basic filtering to exclude likely placeholders or icons
                    # If we find a good candidate, take it. Prioritize 'data-src' if present?
                    # Actually, often 'src' is a placeholder.
                    # Let's iterate and take the first "good" http link that doesn't look like a placeholder data:image
                    final_src = src
                    # If it's a data-src and valid, it's usually better than src (often placeholder)
                    # But the list order above puts src first.
                    # Let's change strategy: Look for specific attributes first.
                    break

            # Re-eval strategy: Check specific attributes in order of preference for "real" content
            ordered_candidates = [
                img.get("data-src"),
                img.get("data-original"),
                img.get("data-url"),
                img.get("src"),  # Fallback to src
            ]

            if final_src:
                images.append(final_src)

        # Get text
        text = soup.get_text()

        # Break into lines and remove leading and trailing space on each
        lines = (line.strip() for line in text.splitlines())
        # Break multi-headlines into a line each
        chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
        # Drop blank lines
        text = "\n".join(chunk for chunk in chunks if chunk)

        return text, images
    except Exception as e:
        logger.error("Failed to fetch article content from %s: %s", url, e)
        return None, []


def download_image(url: str) -> Optional[Tuple[str, str]]:
    """
    Download image from URL and return (base64_data, media_type).
    Returns None if download fails or constraints not met.
    """
    # pylint: disable=import-outside-toplevel
    import base64

    import requests

    if not url:
        return None

    try:
        # 5 second timeout, 5MB limit
        response = requests.get(url, timeout=5, stream=True)
        response.raise_for_status()

        # Check Content-Type and resolve actual media type
        content_type = response.headers.get("Content-Type", "")
        allowed_types = ["image/jpeg", "image/png", "image/webp", "image/gif"]
        media_type = next(
            (t for t in allowed_types if t in content_type.lower()), None
        )
        if not media_type:
            logger.warning(
                "Skipping image %s: Invalid Content-Type %s", url, content_type
            )
            return None

        # Check Content-Length (if available) - 5MB limit
        content_length = response.headers.get("Content-Length")
        if content_length and int(content_length) > 5 * 1024 * 1024:
            logger.warning(
                "Skipping image %s: Too large (%s bytes)", url, content_length
            )
            return None

        # Download content
        # Use simple content read but watch out for size if stream didn't work
        if len(response.content) > 5 * 1024 * 1024:
            logger.warning("Skipping image %s: Downloaded size too large", url)
            return None

        return base64.b64encode(response.content).decode("utf-8"), media_type

    except Exception as e:
        logger.warning("Failed to download image %s: %s", url, e)
        return None
