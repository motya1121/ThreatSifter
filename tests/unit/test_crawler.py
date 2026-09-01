import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

# Add lambda/crawler and lambda/layer to path
sys.path.append("lambda/crawler")
sys.path.append("lambda/layer")

import crawler_handler


class TestCrawler(unittest.TestCase):

    @patch("crawler_handler.utils.DynamoDBManager")
    @patch("crawler_handler.feedparser.parse")
    @patch("crawler_handler.sqs")
    def test_process_site_new_article(self, mock_sqs, mock_parse, MockDB):
        # Setup
        db_instance = MockDB.return_value

        # Mock Feed using DICTIONARY for entry, as code uses .get()
        mock_entry = {
            "title": "Test Article",
            "link": "http://example.com/article",
            "published_parsed": (2025, 1, 1, 12, 0, 0, 0, 0, 0),
        }

        mock_feed = MagicMock()
        mock_feed.entries = [mock_entry]
        mock_parse.return_value = mock_feed

        site = {
            "pk": "SITE#1",
            "sk": "META",
            "site_url": "http://example.com/rss",
            "site_name": "Test Site",
            "watcher": "threat-sifter",
            "last_checked_at": "2024-01-01T00:00:00",
        }

        # Execute
        crawler_handler.process_site(site, db_instance)

        # Verify SQS sent
        mock_sqs.send_message.assert_called_once()
        call_args = mock_sqs.send_message.call_args[1]
        body = json.loads(call_args["MessageBody"])
        self.assertEqual(body["title"], "Test Article")

        # Verify DB update
        db_instance.update_last_checked.assert_called_once()

    @patch("crawler_handler.utils.DynamoDBManager")
    @patch("crawler_handler.feedparser.parse")
    def test_process_site_no_new_article(self, mock_parse, MockDB):
        # Setup
        db_instance = MockDB.return_value

        # Mock Feed (Old article)
        mock_entry = {"published_parsed": (2023, 1, 1, 12, 0, 0, 0, 0, 0)}
        mock_feed = MagicMock()
        mock_feed.entries = [mock_entry]
        mock_parse.return_value = mock_feed

        site = {
            "pk": "SITE#1",
            "sk": "META",
            "site_url": "http://example.com/rss",
            "watcher": "threat-sifter",
            "last_checked_at": "2024-01-01T00:00:00",
        }

        # Execute
        crawler_handler.process_site(site, db_instance)

        # Verify No DB update
        db_instance.update_last_checked.assert_not_called()

    @patch("crawler_handler.utils.dynamodb")
    def test_get_active_sites_filtering(self, mock_dynamodb):
        # Setup mock table and query response
        mock_table = MagicMock()
        mock_dynamodb.Table.return_value = mock_table
        
        db_manager = crawler_handler.utils.DynamoDBManager("DummyTable")
        
        # Mock items in DB: some with threat-sifter, some with claude-cowork, some without watcher, empty watcher, None watcher
        mock_table.query.return_value = {
            "Items": [
                {"pk": "site-1", "watcher": "threat-sifter", "status": "ACTIVE"},
                {"pk": "site-2", "watcher": "claude-cowork", "status": "ACTIVE"},
                {"pk": "site-3", "status": "ACTIVE"}, # missing watcher, should default to threat-sifter
                {"pk": "site-4", "watcher": "other-watcher", "status": "ACTIVE"},
                {"pk": "site-5", "watcher": "", "status": "ACTIVE"}, # empty watcher, should default to threat-sifter
                {"pk": "site-6", "watcher": None, "status": "ACTIVE"}, # None watcher, should default to threat-sifter
            ]
        }
        
        # Test 1: Fetch threat-sifter (should return site-1, site-3, site-5, site-6)
        sites = db_manager.get_active_sites(watcher="threat-sifter")
        self.assertEqual(len(sites), 4)
        self.assertEqual({s["pk"] for s in sites}, {"site-1", "site-3", "site-5", "site-6"})
        
        # Test 2: Fetch claude-cowork (should return site-2)
        sites = db_manager.get_active_sites(watcher="claude-cowork")
        self.assertEqual(len(sites), 1)
        self.assertEqual(sites[0]["pk"], "site-2")
        
        # Test 3: Fetch without watcher filter (should return all 6 sites)
        sites = db_manager.get_active_sites()
        self.assertEqual(len(sites), 6)
