import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

# Add lambda/analyzer and lambda/layer to path
sys.path.append("lambda/analyzer")
sys.path.append("lambda/layer")

import analyzer_handler


class TestAnalyzer(unittest.TestCase):

    @patch("analyzer_handler.utils.BedrockClient")
    @patch("analyzer_handler.utils.DynamoDBManager")
    @patch("analyzer_handler.utils.slack_notify")
    @patch("analyzer_handler.utils.get_ssm_parameter")
    def test_process_record_threat(self, mock_get_ssm, mock_slack, MockDB, MockBedrock):
        # Setup
        os.environ["SLACK_TOKEN_PARAM"] = "/test/param"
        mock_get_ssm.return_value = "test-token"
        bedrock_instance = MockBedrock.return_value
        db_instance = MockDB.return_value
        # ... (rest of function setup)

        # Triage says YES
        bedrock_instance.invoke_triage.return_value = {
            "is_threat": True,
            "reason": "Test",
        }

        # Analysis result
        bedrock_instance.invoke_analysis.return_value = {
            "summary": "Malicious",
            "ioc": [{"type": "IP", "value": "1.1.1.1"}],
            "malware_info": [{"name": "TestMalware"}],
        }

        message = {
            "article_url": "http://example.com",
            "title": "Threat Alert",
            "summary": "Dangerous",
            "published_at": "2025-01-01T00:00:00",
            "site_pk": "site-1234567890abcdef",
        }

        # Execute
        analyzer_handler.process_record(
            message, db_instance, bedrock_instance, "req-123"
        )

        # Verify Bedrock calls
        bedrock_instance.invoke_triage.assert_called_once()
        bedrock_instance.invoke_analysis.assert_called_once()

        # Verify DB Save
        db_instance.save_article.assert_called_once()
        saved_item = db_instance.save_article.call_args[0][0]
        self.assertEqual(saved_item["category"], "Article")
        db_instance.batch_write_items.assert_called_once()

        # Verify SSM and Slack
        mock_get_ssm.assert_called_with("/test/param")
        mock_slack.assert_called_once()

    @patch("analyzer_handler.utils.BedrockClient")
    @patch("analyzer_handler.utils.DynamoDBManager")
    @patch("analyzer_handler.utils.slack_notify")
    @patch("analyzer_handler.utils.get_ssm_parameter")
    def test_process_record_not_threat(
        self, mock_get_ssm, mock_slack, MockDB, MockBedrock
    ):
        # Setup
        os.environ["SLACK_TOKEN_PARAM"] = "/test/param"
        bedrock_instance = MockBedrock.return_value
        db_instance = MockDB.return_value

        # Triage says NO
        bedrock_instance.invoke_triage.return_value = {"is_threat": False}

        message = {
            "article_url": "http://example.com",
            "title": "Safe Article",
            "summary": "Nothing to see",
            "published_at": "2025-01-01T00:00:00",
        }

        # Execute
        analyzer_handler.process_record(
            message, MockDB.return_value, bedrock_instance, "req-123"
        )

        # Verify DB Saved (for Stats)
        db_instance.save_article.assert_called_once()
        saved_item = db_instance.save_article.call_args[0][0]
        self.assertEqual(saved_item["processing_status"], "TRIAGE_DROPPED")
        self.assertEqual(
            saved_item.get("category"), "Article"
        )  # Even dropped items get meta, so let's tag them too?
        # Checked analyzer_handler: dropped items get category?
        # Wait, I added it to both `article_item` definitions in analyzer_handler.py.
        # Let's verify line 115-123 in analyzer_handler.py

        # Verify skipped analysis
        bedrock_instance.invoke_analysis.assert_not_called()
        mock_slack.assert_not_called()

    @patch("analyzer_handler.utils.BedrockClient")
    @patch("analyzer_handler.utils.DynamoDBManager")
    @patch("analyzer_handler.utils.slack_notify")
    @patch("analyzer_handler.utils.get_ssm_parameter")
    def test_process_record_threat_empty(
        self, mock_get_ssm, mock_slack, MockDB, MockBedrock
    ):
        # Setup
        os.environ["SLACK_TOKEN_PARAM"] = "/test/param"
        mock_get_ssm.return_value = "test-token"
        bedrock_instance = MockBedrock.return_value
        db_instance = MockDB.return_value

        # Triage says YES
        bedrock_instance.invoke_triage.return_value = {
            "is_threat": True,
            "reason": "Test",
        }

        # Analysis result EMPTY (No IoC/IoA/Malware)
        bedrock_instance.invoke_analysis.return_value = {
            "summary": "No specific threat details found.",
            "ioc": [],
            "ioa": [],
            "malware_behavior": [],
        }

        message = {
            "article_url": "http://example.com",
            "title": "Vague Threat",
            "summary": "Maybe dangerous",
            "published_at": "2025-01-01T00:00:00",
            "site_pk": "site-123",
        }

        # Execute
        analyzer_handler.process_record(
            message, db_instance, bedrock_instance, "req-123"
        )

        # Verify Analysis Called
        bedrock_instance.invoke_analysis.assert_called_once()

        # Verify DB Saved (for Stats)
        db_instance.save_article.assert_called_once()
        saved_item = db_instance.save_article.call_args[0][0]
        self.assertEqual(saved_item["processing_status"], "ANALYSIS_EMPTY")
        self.assertEqual(saved_item["category"], "Article")

        # Batch write still not called (no child items)
        db_instance.batch_write_items.assert_not_called()

        # Verify Notification SENT (with 'No threat info found')
        mock_slack.assert_called_once()
        args, _ = mock_slack.call_args
        self.assertIn("Status: No threat info found", args[0])
