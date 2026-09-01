import json
import logging
import os
import random
import secrets
from datetime import datetime

from botocore.exceptions import ClientError
from common import utils  # From Lambda Layer

# Logging setup
logger = logging.getLogger()
logger.setLevel(os.getenv("LOG_LEVEL", "INFO"))


def lambda_handler(event, context):
    """Lambda Handler for Article Analyzer."""
    # pylint: disable=unused-argument
    logger.info("Starting Article Analyzer")

    db_manager = utils.DynamoDBManager()
    bedrock = utils.BedrockClient()

    # Context has request_id
    request_id = context.aws_request_id if context else "UNKNOWN_REQUEST_ID"

    for record in event.get("Records", []):
        body = {}  # ensure body is always defined for error handling
        try:
            body = json.loads(record["body"])
            process_record(body, db_manager, bedrock, request_id)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ThrottlingException":
                logger.error(
                    "ThrottlingException encountered. Re-raising to trigger SQS retry."
                )
                raise
            logger.error("Failed to process record (ClientError): %s", e)
            continue
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.error("Failed to process record: %s", e)

            receive_count = int(
                record.get("attributes", {}).get("ApproximateReceiveCount", 1)
            )

            if receive_count >= 4:
                # Final attempt: notify Slack and discard without sending to DLQ
                logger.warning(
                    "Final attempt reached (%d). Discarding message.", receive_count
                )
                slack_token_param = os.getenv("SLACK_TOKEN_PARAM")
                slack_token = utils.get_ssm_parameter(slack_token_param)
                if slack_token:
                    title = body.get("title", "Unknown")
                    article_url = body.get("article_url", "Unknown")
                    notify_text = (
                        f"⚠️ *Analysis Failed* (attempt {receive_count}/4)\n"
                        f"<{article_url}|{title}>\n"
                        f"Error: `{e}`"
                    )
                    utils.slack_notify(notify_text, slack_token)
                continue

            # Random backoff for visibility timeout (3min - 5min)
            queue_url = os.getenv("SQS_QUEUE_URL")
            receipt_handle = record.get("receiptHandle")

            if queue_url and receipt_handle:
                backoff_seconds = random.randint(180, 300)
                logger.info(
                    "Applying random backoff of %ds for failed message", backoff_seconds
                )
                utils.change_message_visibility(
                    queue_url, receipt_handle, backoff_seconds
                )

            # Re-raise to trigger SQS retry
            raise

    logger.info("Analyzer finished.")


def process_record(
    message: dict,
    db_manager: utils.DynamoDBManager,
    bedrock: utils.BedrockClient,
    request_id: str,
):
    """Process a single article message."""
    article_url = message.get("article_url")
    site_pk = message.get("site_pk")  # Expected format: site-<16HEX>
    title = message.get("title")
    summary = message.get("summary")
    published_at = message.get("published_at")

    if not article_url:
        logger.warning("No article URL in message")
        return

    logger.info("Analyzing article: %s", title)

    # Determine Models
    triage_model_id = message.get("triage_model_id") or os.getenv("TRIAGE_MODEL_ID")
    analysis_model_id = message.get("analysis_model_id") or os.getenv(
        "ANALYZER_MODEL_ID"
    )

    # Fetch full article content first
    logger.info("Fetching full article content from: %s", article_url)
    full_content, image_urls = utils.fetch_article_content(article_url)

    if full_content:
        logger.info(
            "Successfully fetched content (length: %d, images: %d)",
            len(full_content),
            len(image_urls),
        )
        input_text = full_content
    else:
        logger.warning("Failed to fetch content or empty. Falling back to summary.")
        input_text = summary
        image_urls = []

    # 1. Triage
    triage_text = f"Title: {title}\nContent: {input_text}"
    triage_result = bedrock.invoke_triage(
        triage_text, image_urls=image_urls, model_id=triage_model_id
    )

    if "error" in triage_result:
        logger.error(
            "Triage failed with error: %s. Raising exception to trigger retry.",
            triage_result["error"],
        )
        raise ValueError(f"Triage failed: {triage_result['error']}")

    is_threat = triage_result.get("is_threat", False)
    logger.info(
        "Triage Result: %s (Reason: %s)", is_threat, triage_result.get("reason")
    )

    if not is_threat:
        logger.info("Article skipped based on triage. Saving trace for stats.")
        # Save Triage Drop Result
        art_hex = secrets.token_hex(8)
        article_id = f"article-{art_hex}"

        article_item = {
            "pk": article_id,
            "sk": "META",
            "article_id": article_id,
            "site_id": site_pk if site_pk else "UNKNOWN_SITE",
            "published_at": published_at,
            "article_url": article_url,
            "title": title,
            "category": "Article",  # For TypeIndex query
            "created_at": datetime.now().isoformat(),
            "triage_result": json.dumps(triage_result, ensure_ascii=False),
            "summary": triage_result.get("summary", ""),
            # Explicit status for stats
            "processing_status": "TRIAGE_DROPPED",
            "model_name": triage_model_id or "Claude 3 Haiku",
            "processing_request_id": request_id,
            "is_read": False,
            "unread_flag": "1",  # For UnreadIndex GSI
            "feedback": "",
            "feedback_reviewed": False,
            # TTL ?
        }
        db_manager.save_article(article_item)
        return

    # 2. Detailed Analysis
    relevant_image_urls = triage_result.get("relevant_image_urls", [])
    downloaded_images = []

    if relevant_image_urls:
        logger.info(
            "Downloading %d relevant images for analysis", len(relevant_image_urls)
        )
        for img_url in relevant_image_urls:
            result = utils.download_image(img_url)
            if result:
                downloaded_images.append(result)
        logger.info("Successfully downloaded %d images", len(downloaded_images))

    analysis_text = f"Title: {title}\nContent: {input_text}"
    analysis_result = bedrock.invoke_analysis(
        analysis_text, images=downloaded_images, model_id=analysis_model_id
    )

    if "error" in analysis_result:
        if analysis_result.get("refusal"):
            logger.warning("Analysis skipped due to model refusal: %s", analysis_result["error"])
            return
        logger.error(
            "Analysis failed with error: %s. Raising exception to trigger retry.",
            analysis_result["error"],
        )
        raise ValueError(f"Analysis failed: {analysis_result['error']}")

    # 3. Create Child Items (IoC, IoA, Malware)
    # Generate ID: article-<16HEX>
    art_hex = secrets.token_hex(8)
    article_id = f"article-{art_hex}"

    items_to_save = []

    # Helper to clean/hash values for SK
    def generate_sk_suffix(content):
        return secrets.token_hex(8)

    # IoCs
    for ioc in analysis_result.get("ioc", []):
        try:
            val = ioc.get("value")
            if not val:
                continue

            sk_suffix = generate_sk_suffix(val)
            item = {
                "pk": article_id,
                "sk": f"IOC#{sk_suffix}",
                "category": "IoC",
                "published_at": published_at,
                "indicator": val,  # Searchable via IndicatorIndex
                "type": ioc.get("type", "Unknown"),
                "value": val,
                "context": ioc.get("context", ""),
                "model_name": analysis_model_id,
            }
            items_to_save.append(item)
        except Exception as e:
            logger.error("Error processing IoC item: %s", e)

    # IoAs
    for ioa in analysis_result.get("ioa", []):
        try:
            val = ioa.get("value")
            if not val:
                continue

            sk_suffix = generate_sk_suffix(val)
            item = {
                "pk": article_id,
                "sk": f"IOA#{sk_suffix}",
                "category": "IoA",
                "published_at": published_at,
                "indicator": val[:100],
                "type": ioa.get("type", "Unknown"),
                "value": val,
                "description": ioa.get("description", ""),
                "model_name": analysis_model_id,
            }
            items_to_save.append(item)
        except Exception as e:
            logger.error("Error processing IoA item: %s", e)

    # Malware Behavior
    for mal in analysis_result.get("malware_behavior", []):
        try:
            name = mal.get("malware_name")
            if not name:
                continue

            sk_suffix = generate_sk_suffix(name + (mal.get("behavior") or ""))
            item = {
                "pk": article_id,
                "sk": f"MALWARE#{sk_suffix}",
                "category": "MalBehavior",
                "published_at": published_at,
                "indicator": name,
                "malware_name": name,
                "behavior": mal.get("behavior", ""),
                "model_name": analysis_model_id,
            }
            items_to_save.append(item)
        except Exception as e:
            logger.error("Error processing Malware item: %s", e)

    # Determine Status
    if items_to_save:
        status = "THREAT_DETECTED"
    else:
        status = "ANALYSIS_EMPTY"
        logger.info("No threat info found. Saving metadata for stats.")

    # Save Article Meta ALWAYS (for stats)
    article_item = {
        "pk": article_id,
        "sk": "META",
        "article_id": article_id,
        "site_id": site_pk if site_pk else "UNKNOWN_SITE",
        "published_at": published_at,
        "article_url": article_url,
        "title": title,
        "summary": analysis_result.get("summary", summary or ""),
        "category": "Article",  # For TypeIndex query
        "created_at": datetime.now().isoformat(),
        "triage_result": json.dumps(triage_result, ensure_ascii=False),
        "analysis_result": json.dumps(analysis_result, ensure_ascii=False),
        "processing_status": status,
        "model_name": analysis_model_id or "Claude 3.5 Sonnet",
        "processing_request_id": request_id,
        "is_read": False,
        "unread_flag": "1",  # For UnreadIndex GSI
        "feedback": "",
        "feedback_reviewed": False,
    }
    db_manager.save_article(article_item)

    if items_to_save:
        db_manager.batch_write_items(items_to_save)
        logger.info("Saved article and %d threat details.", len(items_to_save))

    # 4. Notify Slack
    slack_token_param = os.getenv("SLACK_TOKEN_PARAM")
    slack_token = utils.get_ssm_parameter(slack_token_param)

    if slack_token:
        # Construct message
        if not items_to_save:
            # Special notification for Empty Results
            message_text = (
                f"⚠️ *Analysis Results Empty* ⚠️\n"
                f"<{article_url}|{title}>\n"
                f"Model: {analysis_model_id}\n"
                f"Status: No threat info found (DB Save Skipped)\n"
                f"(`ArticleID: {article_id}`)\n"
            )
        else:
            # Detailed Notification
            ioc_list = [
                f"• `{i['value']}` ({i['type']})\n   Context: {i.get('context', 'N/A')}"
                for i in items_to_save
                if i["category"] == "IoC"
            ]
            ioa_list = [
                f"• [{i['type']}] `{i.get('value', 'N/A')}`\n   {i['description']}"
                for i in items_to_save
                if i["category"] == "IoA"
            ]
            mal_list = [
                f"• **{i['malware_name']}**\n   {i['behavior']}"
                for i in items_to_save
                if i["category"] == "MalBehavior"
            ]

            ioc_section = (
                f"*IoCs ({len(ioc_list)}):*\n" + "\n".join(ioc_list[:5])
                if ioc_list
                else "*IoCs:* None"
            )
            ioa_section = (
                f"*IoAs ({len(ioa_list)}):*\n" + "\n".join(ioa_list[:3])
                if ioa_list
                else "*IoAs:* None"
            )
            mal_section = (
                f"*Malware ({len(mal_list)}):*\n" + "\n".join(mal_list[:3])
                if mal_list
                else "*Malware:* None"
            )

            message_text = (
                f"🚨 *Threat Intelligence Alert* 🚨\n"
                f"<{article_url}|{title}>\n\n"
                f"*Summary:*\n{analysis_result.get('summary', 'No summary')}\n\n"
                f"{ioc_section}\n\n"
                f"{ioa_section}\n\n"
                f"{mal_section}\n\n"
                f"(`ArticleID: {article_id}`)\n"
                f"Inspect: `uv run manage.py debug inspect --article-id {article_id}`"
            )
        utils.slack_notify(message_text, slack_token)
    else:
        logger.info("Skipping Slack notification (No Token linked)")
