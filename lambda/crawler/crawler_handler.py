import json
import logging
import os
import time
from datetime import datetime

import feedparser
from common import utils  # From Lambda Layer

# Logging setup
logger = logging.getLogger()
logger.setLevel(os.getenv("LOG_LEVEL", "INFO"))

# Clients
sqs = utils.sqs  # Use shared client from utils
QUEUE_URL = os.getenv("SQS_QUEUE_URL")


def lambda_handler(event, context):
    """Lambda Handler for RSS Crawler."""
    # pylint: disable=unused-argument
    logger.info("Starting RSS Crawler")

    db_manager = utils.DynamoDBManager()

    # 1. Get active sites
    logger.info("Fetching active sites for threat-sifter")
    try:
        sites = db_manager.get_active_sites(watcher="threat-sifter")
    except Exception as e:  # pylint: disable=broad-exception-caught
        logger.error("Failed to get active sites: %s", e)
        return

    logger.info("Found %d active sites for threat-sifter.", len(sites))

    for site in sites:
        process_site(site, db_manager)

    logger.info("Crawler finished.")


def process_site(site: dict, db_manager: utils.DynamoDBManager):
    """Process a single site."""
    site_url = site.get("site_url")
    if not site_url:
        return

    # Parse PK/SK to get IDs if needed
    site_pk = site.get("pk")
    site_sk = site.get("sk")
    last_checked_str = site.get("last_checked_at", "1970-01-01T00:00:00")

    logger.info("Crawling %s, last checked: %s", site_url, last_checked_str)

    try:
        feed = feedparser.parse(site_url)
    except Exception as e:  # pylint: disable=broad-exception-caught
        logger.error("Failed to parse feed %s: %s", site_url, e)
        return

    if not feed.entries:
        logger.warning("No entries found for %s", site_url)
        return

    # Fetch existing URLs for this site to prevent duplicates
    existing_urls = db_manager.get_site_article_urls(site_pk)

    # Deduplicate entries by link before processing
    unique_entries = []
    seen_links = set()
    for entry in feed.entries:
        link = entry.get("link")
        if link and link not in seen_links:
            seen_links.add(link)
            unique_entries.append(entry)

    new_messages = []
    latest_pub_date = last_checked_str

    for entry in unique_entries:
        # Normalize pub date
        dt_struct = entry.get("published_parsed") or entry.get("updated_parsed")
        if not dt_struct:
            continue

        pub_dt = datetime.fromtimestamp(time.mktime(dt_struct))
        pub_date_iso = pub_dt.isoformat()

        # Check if new based on date AND comparison with DB
        article_url = entry.get("link")
            
        if pub_date_iso > last_checked_str:
            if article_url in existing_urls:
                logger.debug("Skipping URL already in DB: %s", article_url)
                continue
            
            # Create message for Analyzer
            message = {
                "site_pk": site_pk,
                "site_name": site.get("site_name"),
                "article_url": article_url,
                "title": entry.get("title"),
                "summary": entry.get("summary", ""),
                "published_at": pub_date_iso,
                # Inject Model IDs if configured
                "triage_model_id": os.getenv("TRIAGE_MODEL_ID"),
                "analysis_model_id": os.getenv("ANALYZER_MODEL_ID"),
            }
            new_messages.append(message)

            # Track latest date for creating new checkpoint
            if pub_date_iso > latest_pub_date:
                latest_pub_date = pub_date_iso

    # Batch send to SQS
    if new_messages:
        logger.info("Found %d new articles for %s", len(new_messages), site_url)
        for msg in new_messages:
            try:
                sqs.send_message(QueueUrl=QUEUE_URL, MessageBody=json.dumps(msg))
            except Exception as e:  # pylint: disable=broad-exception-caught
                logger.error("Failed to send SQS message: %s", e)

        # Update last checked
        if latest_pub_date > last_checked_str:
            db_manager.update_last_checked(site_pk, site_sk, latest_pub_date)
    else:
        logger.info("No new articles for %s", site_url)
