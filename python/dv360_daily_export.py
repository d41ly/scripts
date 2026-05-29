import logging
from google.oauth2 import service_account
from googleapiclient import discovery

# Enable logging
logging.basicConfig(level=logging.DEBUG)

PARTNER_ID = "<DV360_PARTNER_ID>"
ADVERTISER_ID = "<DV360_ADVERTISER_ID>"

SCOPES = [
    "https://www.googleapis.com/auth/display-video",
    "https://www.googleapis.com/auth/doubleclickbidmanager",
]

# Path to the service account key file
SERVICE_ACCOUNT_FILE = '<path to service account key file>'

try:
    # Authenticate using the service account
    credentials = service_account.Credentials.from_service_account_file(
        SERVICE_ACCOUNT_FILE, scopes=SCOPES
    )
    
    # Log the service account email
    logging.debug(f"Using service account email: {credentials.service_account_email}")
    
    # Build the API client
    service = discovery.build('doubleclickbidmanager', 'v2', credentials=credentials)

    query = {
        "metadata": {
            "title": "Custom Daily Data Export",
            "dataRange": {"range": "PREVIOUS_DAY"},
            "format": "CSV",
        },
        "params": {
            "type": "STANDARD",
            "groupBys": [
                "FILTER_DATE",
				"FILTER_ADVERTISER_NAME",
                "FILTER_ADVERTISER",
                "FILTER_ADVERTISER_CURRENCY",
                "FILTER_INSERTION_ORDER_NAME",
                "FILTER_INSERTION_ORDER",
                "FILTER_LINE_ITEM_NAME",
                "FILTER_LINE_ITEM",
				"FILTER_CREATIVE",
				"FILTER_COUNTRY",
				],
            "filters": [{"type": "FILTER_PARTNER", "value": f"{PARTNER_ID}"},{"type": "FILTER_ADVERTISER", "value": f"{ADVERTISER_ID}"}],
            "metrics": [
                "METRIC_IMPRESSIONS",
                "METRIC_BILLABLE_IMPRESSIONS",
                "METRIC_CLICKS",
                "METRIC_CTR",
                "METRIC_TOTAL_CONVERSIONS",
                "METRIC_TOTAL_MEDIA_COST_USD",
                "METRIC_MEDIA_COST_ADVERTISER",
            ],
            "options": {},
        },
        "schedule": {"frequency": "ONE_TIME"},
    }

    # Create a query, fetch its id
    response = service.queries().create(body=query).execute()
    queryId = response.get("queryId")

    try:
        # Run a query (i.e., create a report)
        response = service.queries().run(queryId=queryId, synchronous=True).execute()
        
        # Print URL to report
        print(response["metadata"]["googleCloudStoragePath"])
    except Exception as e:
        logging.error(f"Error running query: {e}")

    service.queries().delete(queryId=queryId).execute()

except Exception as e:
    logging.error(f"Error setting up service: {e}")