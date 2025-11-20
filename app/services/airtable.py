"""
Airtable Service for Pizza Grants and Club Management
"""
import os
import json
import logging
import requests
import urllib.parse
import secrets
import string
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

app = None
db = None
User = None
Club = None
filter_profanity_comprehensive = None


def init_service(flask_app, database, user_model, club_model, profanity_filter):
    """Initialize the service with app context and dependencies"""
    global app, db, User, Club, filter_profanity_comprehensive
    app = flask_app
    db = database
    User = user_model
    Club = club_model
    filter_profanity_comprehensive = profanity_filter


class AirtableService:
    def __init__(self):
        self.api_token = os.environ.get('AIRTABLE_TOKEN')
        self.base_id = os.environ.get('AIRTABLE_BASE_ID', 'appSnnIu0BhjI3E1p')
        self.table_name = os.environ.get('AIRTABLE_TABLE_NAME', 'Grants')
        # New Clubs base configuration
        self.clubs_base_id = os.environ.get('AIRTABLE_CLUBS_BASE_ID', 'appUfrUFraxH3D5Ob')
        self.clubs_table_id = os.environ.get('AIRTABLE_CLUBS_TABLE_ID', 'tblsA5iv6Fz0qxHFC')
        self.clubs_table_name = os.environ.get('AIRTABLE_CLUBS_TABLE_NAME', 'Clubs')
        self.leaders_table_id = os.environ.get('AIRTABLE_LEADERS_TABLE_ID', 'tblGjo7FkEXxF6BQt')
        self.leaders_table_name = os.environ.get('AIRTABLE_LEADERS_TABLE_NAME', 'Leaders')
        self.email_verification_table_name = 'Dashboard Email Verification'
        self.headers = {
            'Authorization': f'Bearer {self.api_token}',
            'Content-Type': 'application/json'
        }
        encoded_table_name = urllib.parse.quote(self.table_name)
        self.base_url = f'https://api.airtable.com/v0/{self.base_id}/{encoded_table_name}'

        self.clubs_base_url = f'https://api.airtable.com/v0/{self.clubs_base_id}/{self.clubs_table_id}'
        self.leaders_base_url = f'https://api.airtable.com/v0/{self.clubs_base_id}/{self.leaders_table_id}'
        self.email_verification_url = f'https://api.airtable.com/v0/{self.clubs_base_id}/{urllib.parse.quote(self.email_verification_table_name)}'

    def _validate_airtable_url(self, url):
        """Validate that URL is a legitimate Airtable API URL to prevent SSRF"""
        try:
            parsed = urllib.parse.urlparse(url)
            return (parsed.scheme in ['https'] and
                   parsed.hostname == 'api.airtable.com' and
                   parsed.path.startswith('/v0/'))
        except:
            return False

    def _safe_request(self, method, url, **kwargs):
        """Make a safe HTTP request with URL validation and timeout"""
        if not self._validate_airtable_url(url):
            raise ValueError(f"Invalid Airtable URL: {url}")

        kwargs.setdefault('timeout', 60)

        if method.upper() == 'GET':
            return requests.get(url, **kwargs)
        elif method.upper() == 'POST':
            return requests.post(url, **kwargs)
        elif method.upper() == 'PATCH':
            return requests.patch(url, **kwargs)
        elif method.upper() == 'DELETE':
            return requests.delete(url, **kwargs)
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")

    def _check_school_variations(self, club_name, venue):
        """Check for common school name variations"""
        common_words = ['high', 'school', 'college', 'university', 'academy', 'the', 'of', 'at']

        club_words = [word for word in club_name.split() if word not in common_words and len(word) > 2]
        venue_words = [word for word in venue.split() if word not in common_words and len(word) > 2]

        for club_word in club_words:
            for venue_word in venue_words:
                if (club_word in venue_word or venue_word in club_word or
                    (club_word.startswith(venue_word[:3]) and len(venue_word) > 3) or
                    (venue_word.startswith(club_word[:3]) and len(club_word) > 3)):
                    return True

        return False

    def verify_club_leader(self, email, club_name):
        if not self.api_token:
            logger.error("Airtable API token not configured")
            return False

        if not self.clubs_base_id or not self.clubs_table_name:
            logger.error("Airtable clubs base ID or table name not configured")
            return False

        if not email or '@' not in email or len(email) < 3:
            logger.error("Invalid email format for verification")
            return False

        escaped_email = email.replace('"', '""').replace("'", "''")

        if email.count('@') != 1:
            logger.error("Invalid email format - multiple @ symbols")
            return False

        try:
            # Note: Leader Email is a lookup field from the Leaders table
            email_filter_params = {
                'filterByFormula': f'{{Leader Email}} = "{escaped_email}"'
            }

            logger.info(f"Verifying club leader: email={email}, club={club_name}")
            logger.debug(f"Airtable URL: {self.clubs_base_url}")
            logger.debug(f"Email filter formula: {email_filter_params['filterByFormula']}")

            parsed_url = urllib.parse.urlparse(self.clubs_base_url)
            if parsed_url.hostname not in ['api.airtable.com']:
                logger.error(f"Invalid Airtable URL hostname: {parsed_url.hostname}")
                return False

            response = self._safe_request('GET', self.clubs_base_url, headers=self.headers, params=email_filter_params)

            logger.info(f"Airtable response status: {response.status_code}")
            logger.debug(f"Airtable response headers: {dict(response.headers)}")
            logger.debug(f"Airtable response content length: {len(response.content) if response.content else 0}")

            if response.status_code == 200:
                try:
                    data = response.json()
                    logger.debug(f"Airtable response data keys: {list(data.keys()) if data else 'None'}")
                    records = data.get('records', [])
                    logger.info(f"Found {len(records)} records with email {email}")
                    if records:
                        logger.debug(f"First record fields: {list(records[0].get('fields', {}).keys()) if records else 'None'}")
                except ValueError as json_error:
                    logger.error(f"Failed to parse Airtable JSON response: {json_error}")
                    logger.error(f"Raw response content: {response.text[:500]}...")
                    return False

                if len(records) == 0:
                    logger.info("No records found with that email address")
                    return False

                club_name_lower = club_name.lower().strip()

                club_names = [record.get('fields', {}).get('Club Name', '') for record in records]
                logger.info(f"Available club names for {email}: {club_names}")
                logger.debug(f"Full record data for debugging: {[record.get('fields', {}) for record in records]}")

                for record in records:
                    fields = record.get('fields', {})
                    venue = fields.get('Club Name', '').lower().strip()
                    logger.debug(f"Checking club name: '{venue}' against requested club name: '{club_name_lower}'")

                    if (club_name_lower in venue or
                        venue.find(club_name_lower) >= 0 or
                        any(word.strip() in venue for word in club_name_lower.split() if len(word.strip()) > 2) or
                        any(word.strip() in club_name_lower for word in venue.split() if len(word.strip()) > 2) or
                        self._check_school_variations(club_name_lower, venue)):
                        logger.info(f"Found matching club: {fields.get('Club Name', '')}")
                        return True

                logger.info(f"No club name match found for '{club_name}' in available clubs: {club_names}")
                return False

            elif response.status_code == 403:
                logger.error(f"Airtable 403 Forbidden - check API token permissions. Response: {response.text}")
                return False
            elif response.status_code == 404:
                logger.error(f"Airtable 404 Not Found - check base ID and table name. Response: {response.text}")
                return False
            else:
                logger.error(f"Airtable API error {response.status_code}: {response.text}")
                return False

        except Exception as e:
            logger.error(f"Exception during Airtable verification: {str(e)}")
            return False

    def get_clubs_by_leader_email(self, email):
        """Get all clubs for a given leader email (includes suspended clubs with status)"""
        if not self.api_token:
            logger.error("Airtable API token not configured")
            return []

        if not self.clubs_base_id or not self.clubs_table_name:
            logger.error("Airtable clubs base ID or table name not configured")
            return []

        if not email or '@' not in email or len(email) < 3:
            logger.error("Invalid email format")
            return []

        escaped_email = email.replace('"', '""').replace("'", "''")

        try:
            # Note: Leader Email is a lookup field from the Leaders table
            email_filter_params = {
                'filterByFormula': f'{{Leader Email}} = "{escaped_email}"'
            }

            logger.info(f"Getting clubs for leader email: {email}")
            
            response = self._safe_request('GET', self.clubs_base_url, headers=self.headers, params=email_filter_params)

            if response.status_code == 200:
                data = response.json()
                records = data.get('records', [])
                logger.info(f"Found {len(records)} clubs for email {email}")
                
                clubs = []
                for record in records:
                    fields = record.get('fields', {})
                    club_name = fields.get('Club Name', 'Unknown Club')
                    # New base uses Venue Name for location
                    location = fields.get('Venue Name', '') or fields.get('Venue City', '')
                    is_suspended = fields.get('Suspension Status', False)

                    clubs.append({
                        'name': club_name,
                        'location': location,
                        'suspended': is_suspended,
                        'airtable_id': record.get('id'),
                        'airtable_data': {
                            'airtable_id': record.get('id'),
                            'name': club_name,
                            'location': location,
                            'venue': fields.get('Venue Name', ''),
                            'suspended': is_suspended,
                            'status': fields.get('Club Status', ''),
                            'meeting_day': fields.get('Est. Day(s) of Meetings', ''),
                            'meeting_time': fields.get('Est. Meeting Length', ''),
                            'website': fields.get('Website', ''),
                            'slack_channel': fields.get('Slack Channel', ''),
                            'github': fields.get('GitHub', ''),
                            'latitude': fields.get('venue_lat'),
                            'longitude': fields.get('venue_lng'),
                            'country': fields.get('Venue Country', ''),
                            'leader_emails': fields.get("Leader Email", ''),
                            'team_notes': fields.get('Team Notes', '').strip() if fields.get('Team Notes') else '',
                        }
                    })
                    
                    if is_suspended:
                        logger.info(f"Club {club_name} is marked as suspended")
                
                logger.info(f"Returning {len(clubs)} clubs (including {sum(1 for c in clubs if c.get('suspended'))} suspended)")
                return clubs
            else:
                logger.error(f"Airtable API error {response.status_code}: {response.text}")
                return []

        except Exception as e:
            logger.error(f"Exception getting clubs by email: {str(e)}")
            return []

    def log_pizza_grant(self, submission_data):
        if not self.api_token:
            logger.error("Airtable API token not configured")
            return None

        try:
            hours = float(submission_data.get('project_hours', 0))

            grant_amount = min(hours * 5, 20)  # $5/hour, max $20

            grant_amount = int(grant_amount)

            if grant_amount > 0:
                is_in_person = submission_data.get('is_in_person_meeting', False)
                club_member_count = submission_data.get('club_member_count', 0)

                if not is_in_person:
                    grant_amount = 0
                    logger.info(f"Grant denied: Not an in-person meeting")
                elif club_member_count < 3:
                    grant_amount = 0
                    logger.info(f"Grant denied: Club has {club_member_count} members, need 3+")
                else:
                    logger.info(f"Grant approved: ${grant_amount} for {hours} hours (in-person meeting, {club_member_count} members)")

            project_table_name = urllib.parse.quote('YSWS Project Submission')
            project_url = f'https://api.airtable.com/v0/{self.base_id}/{project_table_name}'

            fields = {
                'Code URL': submission_data.get('github_url', ''),
                'Playable URL': submission_data.get('live_url', ''),
                'First Name': submission_data.get('first_name', ''),
                'Last Name': submission_data.get('last_name', ''),
                'Email': submission_data.get('email', ''),
                'Age': submission_data.get('age', ''),
                'Status': 'Pending',
                'Decision Reason': '',
                'How did you hear about this?': 'Through Club Leader',
                'What are we doing well?': submission_data.get('doing_well', ''),
                'How can we improve?': submission_data.get('improve', ''),
                'Screenshot': [{'url': submission_data.get('screenshot_url', '')}] if submission_data.get('screenshot_url') else [],
                'Description': submission_data.get('project_description', ''),
                'GitHub Username': submission_data.get('github_username', ''),
                'Address (Line 1)': submission_data.get('address_1', ''),
                'Address (Line 2)': submission_data.get('address_2', ''),
                'City': submission_data.get('city', ''),
                'State / Province': submission_data.get('state', ''),
                'Country': submission_data.get('country', ''),
                'ZIP / Postal Code': submission_data.get('zip', ''),
                'Birthday': submission_data.get('birthday', ''),
                'Hackatime Project': submission_data.get('project_name', ''),
                'Hours': float(hours),
                'Grant Amount': float(grant_amount),
                'Club Name': submission_data.get('club_name', ''),
                'Leader Email': submission_data.get('leader_email', ''),
                'In-Person Meeting': 'Yes' if submission_data.get('is_in_person_meeting', False) else 'No',
                'Club Member Count': str(submission_data.get('club_member_count', 0)),
                'Meeting Requirements Met': 'Yes' if (submission_data.get('is_in_person_meeting', False) and submission_data.get('club_member_count', 0) >= 3) else 'No'
            }

            logger.debug(f"Club name in submission_data: '{submission_data.get('club_name', 'NOT_FOUND')}'")
            logger.debug(f"Leader email in submission_data: '{submission_data.get('leader_email', 'NOT_FOUND')}'")

            fields_before_filter = fields.copy()
            fields = {k: v for k, v in fields.items() if v not in [None, '', []]}

            filtered_out = set(fields_before_filter.keys()) - set(fields.keys())
            if filtered_out:
                logger.debug(f"Fields filtered out due to empty values: {filtered_out}")

            payload = {'records': [{'fields': fields}]}

            logger.info(f"Submitting to Airtable: {project_url}")
            logger.debug(f"Airtable payload fields: {list(fields.keys())}")
            logger.info(f"Screenshot field value: {fields.get('Screenshot', 'NOT_FOUND')}")
            logger.debug(f"Full payload: {payload}")

            response = requests.post(project_url, headers=self.headers, json=payload)

            logger.info(f"Airtable response status: {response.status_code}")
            if response.status_code not in [200, 201]:
                logger.error(f"Airtable submission failed: {response.text}")
                return None

            logger.info("Successfully submitted to Airtable")
            return response.json()

        except Exception as e:
            logger.error(f"Exception in log_pizza_grant: {str(e)}")
            return None

    def submit_pizza_grant(self, grant_data):
        """Submit pizza grant to Grants table"""
        if not self.api_token:
            return None

        grants_table_name = urllib.parse.quote('Grants')
        grants_url = f'https://api.airtable.com/v0/{self.base_id}/{grants_table_name}'

        fields = {
            'Club': grant_data.get('club_name', ''),
            'Email': grant_data.get('contact_email', ''),
            'Status': 'In progress',
            'Grant Amount': float(grant_data.get('grant_amount', 0)),
            'Grant Type': 'Pizza Card',
            'Address': grant_data.get('club_address', ''),
            'Order ID': grant_data.get('order_id', '')
        }

        payload = {'records': [{'fields': fields}]}

        try:
            response = requests.post(grants_url, headers=self.headers, json=payload)
            logger.debug(f"Airtable response status: {response.status_code}")
            logger.debug(f"Airtable response body: {response.text}")
            if response.status_code in [200, 201]:
                return response.json()
            else:
                logger.error(f"Airtable error: {response.text}")
                return None
        except Exception as e:
            logger.error(f"Exception submitting to Airtable: {str(e)}")
            return None

    def submit_purchase_request(self, purchase_data):
        """Submit purchase request to Grant Fulfillment table"""
        if not self.api_token:
            return None

        fulfillment_table_name = urllib.parse.quote('Grant Fulfillment')
        fulfillment_url = f'https://api.airtable.com/v0/{self.base_id}/{fulfillment_table_name}'

        fields = {
            'Leader First Name': purchase_data.get('leader_first_name', ''),
            'Leader Last Name': purchase_data.get('leader_last_name', ''),
            'Leader Email': purchase_data.get('leader_email', ''),
            'Purchase Type': purchase_data.get('purchase_type', ''),
            'Purchase Description': purchase_data.get('description', ''),
            'Purchase Reason': purchase_data.get('reason', ''),
            'Fulfillment Method': purchase_data.get('fulfillment_method', ''),
            'Status': 'Pending',
            'Club Name': purchase_data.get('club_name', ''),
            'Amount': str(purchase_data.get('amount', 0))
        }

        payload = {'records': [{'fields': fields}]}

        try:
            response = requests.post(fulfillment_url, headers=self.headers, json=payload)
            logger.debug(f"Airtable Grant Fulfillment response status: {response.status_code}")
            logger.debug(f"Airtable Grant Fulfillment response body: {response.text}")
            if response.status_code in [200, 201]:
                return response.json()
            else:
                logger.error(f"Airtable Grant Fulfillment error: {response.text}")
                return None
        except Exception as e:
            logger.error(f"Exception submitting to Airtable Grant Fulfillment: {str(e)}")
            return None

    def get_pizza_grant_submissions(self):
        if not self.api_token:
            return []

        try:
            project_table_name = urllib.parse.quote('YSWS Project Submission')
            project_url = f'https://api.airtable.com/v0/{self.base_id}/{project_table_name}'

            response = requests.get(project_url, headers=self.headers)
            if response.status_code == 200:
                data = response.json()
                records = data.get('records', [])

                submissions = []
                for record in records:
                    fields = record.get('fields', {})
                    submissions.append({
                        'id': record['id'],
                        'project_name': fields.get('Hackatime Project', ''),
                        'first_name': fields.get('First Name', ''),
                        'last_name': fields.get('Last Name', ''),
                        'email': fields.get('Email', ''),
                        'club_name': fields.get('Club Name', fields.get('Hack Club', '')),
                        'description': fields.get('Description', ''),
                        'github_url': fields.get('Code URL', ''),
                        'live_url': fields.get('Playable URL', ''),
                        'doing_well': fields.get('What are we doing well?', ''),
                        'improve': fields.get('How can we improve?', ''),
                        'address_1': fields.get('Address (Line 1)', ''),
                        'city': fields.get('City', ''),
                        'state': fields.get('State / Province', ''),
                        'zip': fields.get('ZIP / Postal Code', ''),
                        'country': fields.get('Country', ''),
                        'hours': fields.get('Hours', 0),
                        'grant_amount': fields.get('Grant Amount Override') or fields.get('Grant Amount', ''),
                        'status': fields.get('Status', fields.get('Grant Status', fields.get('Review Status', 'Pending'))),
                        'created_time': record.get('createdTime', '')
                    })

                return submissions
            else:
                logger.error(f"Failed to fetch submissions: {response.status_code} - {response.text}")
                return []
        except Exception as e:
            logger.error(f"Error fetching pizza grant submissions: {str(e)}")
            return []

    def get_submission_by_id(self, submission_id):
        if not self.api_token:
            return None

        try:
            project_table_name = urllib.parse.quote('YSWS Project Submission')
            project_url = f'https://api.airtable.com/v0/{self.base_id}/{project_table_name}'
            url = f"{project_url}/{submission_id}"

            response = requests.get(url, headers=self.headers)
            if response.status_code == 200:
                data = response.json()
                fields = data.get('fields', {})
                return {
                    'id': data['id'],
                    'project_name': fields.get('Hackatime Project', ''),
                    'hours': fields.get('Hours', 0),
                    'status': 'Submitted'
                }
            return None
        except Exception as e:
            logger.error(f"Error fetching submission {submission_id}: {str(e)}")
            return None

    def update_submission_status(self, submission_id, action):
        if not self.api_token:
            return False

        try:
            project_table_name = urllib.parse.quote('YSWS Project Submission')
            project_url = f'https://api.airtable.com/v0/{self.base_id}/{project_table_name}'
            url = f"{project_url}/{submission_id}"

            status = 'Approved' if action == 'approve' else 'Rejected'

            get_response = requests.get(url, headers=self.headers)
            if get_response.status_code == 200:
                current_record = get_response.json()
                fields = current_record.get('fields', {})
                logger.info(f"Current record fields: {list(fields.keys())}")

            possible_status_fields = ['Status', 'Grant Status', 'Review Status', 'Approval Status']

            for field_name in possible_status_fields:
                update_data = {
                    'fields': {
                        field_name: status
                    }
                }

                response = requests.patch(url, headers=self.headers, json=update_data)

                if response.status_code == 200:
                    logger.info(f"Submission {submission_id} status updated to {status} using field '{field_name}'")
                    return True
                else:
                    logger.debug(f"Failed to update with field '{field_name}': {response.status_code} - {response.text}")

            logger.error(f"Failed to update submission status with any field name. Last response: {response.status_code} - {response.text}")
            return False
        except Exception as e:
            logger.error(f"Error updating submission status: {str(e)}")
            return False

    def delete_submission(self, submission_id):
        if not self.api_token:
            return False

        try:
            project_table_name = urllib.parse.quote('YSWS Project Submission')
            project_url = f'https://api.airtable.com/v0/{self.base_id}/{project_table_name}'
            url = f"{project_url}/{submission_id}"

            response = requests.delete(url, headers=self.headers)
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Error deleting submission: {str(e)}")
            return False

    def get_all_clubs_from_airtable(self):
        """Fetch all clubs from Airtable"""
        if not self.api_token:
            logger.error("Cannot fetch clubs from Airtable: API token not configured")
            return []

        try:
            logger.info("Starting to fetch all clubs from Airtable")
            logger.debug(f"Using Airtable URL: {self.clubs_base_url}")
            all_records = []
            offset = None
            page_count = 0

            while True:
                page_count += 1
                params = {}
                if offset:
                    params['offset'] = offset

                logger.debug(f"Fetching page {page_count} with offset: {offset}")
                response = requests.get(self.clubs_base_url, headers=self.headers, params=params)
                logger.debug(f"Page {page_count} response status: {response.status_code}")

                if response.status_code != 200:
                    logger.error(f"Airtable API error on page {page_count}: {response.status_code} - {response.text}")
                    logger.error(f"Request headers: {self.headers}")
                    logger.error(f"Request params: {params}")
                    break

                try:
                    data = response.json()
                    page_records = data.get('records', [])
                    all_records.extend(page_records)
                    logger.debug(f"Page {page_count}: Retrieved {len(page_records)} records, total so far: {len(all_records)}")

                    offset = data.get('offset')
                    if not offset:
                        logger.info(f"Completed fetching all clubs from Airtable. Total records: {len(all_records)}")
                        break
                except ValueError as json_error:
                    logger.error(f"Failed to parse Airtable JSON response on page {page_count}: {json_error}")
                    logger.error(f"Raw response content: {response.text[:500]}...")
                    break

            clubs = []
            logger.debug(f"Processing {len(all_records)} Airtable records into club data")
            for i, record in enumerate(all_records):
                fields = record.get('fields', {})
                logger.debug(f"Processing record {i+1}/{len(all_records)}: ID={record.get('id')}, Fields keys: {list(fields.keys())}")

                # Leader Email is a lookup field that returns an array
                leader_email_field = fields.get("Leader Email", [])
                leader_email = leader_email_field[0] if isinstance(leader_email_field, list) and leader_email_field else (leader_email_field if isinstance(leader_email_field, str) else '')

                club_data = {
                    'airtable_id': record['id'],
                    'name': fields.get('Club Name', '').strip(),
                    'leader_email': leader_email.strip() if leader_email else '',
                    'location': (fields.get('Venue Name', '') or fields.get('Venue City', '')).strip(),
                    'description': fields.get('Description', '').strip(),
                    'status': fields.get('Club Status', '').strip(),
                    'meeting_day': str(fields.get('Est. Day(s) of Meetings', '')).strip(),
                    'meeting_time': fields.get('Est. Meeting Length', '').strip(),
                    'website': fields.get('Website', '').strip(),
                    'slack_channel': fields.get('Slack Channel', '').strip(),
                    'github': fields.get('GitHub', '').strip(),
                    'latitude': fields.get('venue_lat'),
                    'longitude': fields.get('venue_lng'),
                    'country': fields.get('Venue Country', '').strip(),
                    'region': '',  # Not available in new schema
                    'timezone': '',  # Not available in new schema
                    'primary_leader': '',  # Leader info is in separate table
                    'co_leaders': '',  # Co-leader info is in separate table
                    'meeting_notes': fields.get('Description', '').strip(),
                    'club_applications_link': '',  # Not available in new schema
                    'team_notes': fields.get('Team Notes', '').strip(),
                }

                if club_data['name'] and club_data['leader_email']:
                    clubs.append(club_data)
                    logger.debug(f"Added valid club: {club_data['name']} ({club_data['leader_email']})")
                else:
                    logger.debug(f"Skipped invalid club record - Name: '{club_data['name']}', Email: '{club_data['leader_email']}'")

            logger.info(f"Successfully processed {len(clubs)} valid clubs from {len(all_records)} Airtable records")
            return clubs

        except Exception as e:
            logger.error(f"Error fetching clubs from Airtable: {str(e)}")
            return []

    def sync_club_with_airtable(self, club_id, airtable_data):
        """Sync a specific club with Airtable data"""
        try:
            logger.info(f"Starting sync for club ID {club_id} with Airtable data")
            logger.debug(f"Airtable data keys: {list(airtable_data.keys()) if airtable_data else 'None'}")

            club = Club.query.get(club_id)
            if not club:
                logger.error(f"Club with ID {club_id} not found in database")
                return False

            # Check if the Airtable club is suspended
            if airtable_data.get('suspended', False):
                logger.warning(f"Cannot sync club {club_id} - club is suspended in Airtable")
                return False

            logger.debug(f"Found club: {club.name} (current location: {club.location})")

            if 'name' in airtable_data and airtable_data['name']:
                filtered_name = filter_profanity_comprehensive(airtable_data['name'])
                club.name = filtered_name
            else:
                club.name = club.name
            club.location = airtable_data.get('location', club.location)
            if 'description' in airtable_data and airtable_data['description']:
                filtered_description = filter_profanity_comprehensive(airtable_data['description'])
                club.description = filtered_description
            else:
                club.description = club.description

            club.airtable_data = json.dumps({
                'airtable_id': airtable_data.get('airtable_id'),
                'status': airtable_data.get('status'),
                'meeting_day': airtable_data.get('meeting_day'),
                'meeting_time': airtable_data.get('meeting_time'),
                'website': airtable_data.get('website'),
                'slack_channel': airtable_data.get('slack_channel'),
                'github': airtable_data.get('github'),
                'latitude': airtable_data.get('latitude'),
                'longitude': airtable_data.get('longitude'),
                'country': airtable_data.get('country'),
                'region': airtable_data.get('region'),
                'timezone': airtable_data.get('timezone'),
                'primary_leader': airtable_data.get('primary_leader'),
                'co_leaders': airtable_data.get('co_leaders'),
                'meeting_notes': airtable_data.get('meeting_notes'),
                'club_applications_link': airtable_data.get('club_applications_link'),
                'team_notes': airtable_data.get('team_notes'),
            })

            # Sync suspension status from Airtable
            club.is_suspended = airtable_data.get('suspended', False)

            club.updated_at = datetime.now(timezone.utc)
            logger.debug(f"Updated club fields for {club.name}")

            db.session.commit()
            
            # Mark club as onboarded in Airtable
            airtable_id = airtable_data.get('airtable_id')
            if airtable_id:
                self.mark_club_onboarded(airtable_id)
            
            logger.info(f"Successfully synced club {club_id} ({club.name}) with Airtable data")
            return True

        except Exception as e:
            logger.error(f"Error syncing club {club_id} with Airtable: {str(e)}")
            logger.error(f"Exception type: {type(e).__name__}")
            logger.error(f"Exception details: {str(e)}")
            db.session.rollback()
            return False

    def create_club_from_airtable(self, airtable_data):
        """Create a new club from Airtable data"""
        try:
            logger.info(f"Creating new club from Airtable data")
            logger.debug(f"Airtable data: {airtable_data}")

            leader_email = airtable_data.get('leader_email')
            if not leader_email:
                logger.error("Cannot create club: no leader email provided in Airtable data")
                return None

            logger.debug(f"Looking for leader with email: {leader_email}")

            leader = User.query.filter_by(email=leader_email).first()
            if not leader:
                username = leader_email.split('@')[0]
                counter = 1
                original_username = username
                while User.query.filter_by(username=username).first():
                    username = f"{original_username}{counter}"
                    counter += 1

                leader = User(
                    username=username,
                    email=leader_email,
                    first_name=airtable_data.get('primary_leader', '').split(' ')[0] if airtable_data.get('primary_leader') else '',
                    last_name=' '.join(airtable_data.get('primary_leader', '').split(' ')[1:]) if airtable_data.get('primary_leader') else ''
                )
                leader.set_password(secrets.token_urlsafe(16))  # Random password
                db.session.add(leader)
                db.session.flush()

            filtered_name = filter_profanity_comprehensive(airtable_data.get('name'))

            existing_club = Club.query.filter_by(name=filtered_name).first()
            if existing_club:
                logger.warning(f"Skipping club creation from Airtable - duplicate name: {filtered_name}")
                return None

            default_desc = f"Official {filtered_name} Hack Club"
            club_desc = airtable_data.get('description', default_desc)
            filtered_description = filter_profanity_comprehensive(club_desc)
            club = Club(
                name=filtered_name,
                description=filtered_description,
                location=airtable_data.get('location'),
                leader_id=leader.id,
                is_suspended=airtable_data.get('suspended', False),
                airtable_data=json.dumps({
                    'airtable_id': airtable_data.get('airtable_id'),
                    'status': airtable_data.get('status'),
                    'meeting_day': airtable_data.get('meeting_day'),
                    'meeting_time': airtable_data.get('meeting_time'),
                    'website': airtable_data.get('website'),
                    'slack_channel': airtable_data.get('slack_channel'),
                    'github': airtable_data.get('github'),
                    'latitude': airtable_data.get('latitude'),
                    'longitude': airtable_data.get('longitude'),
                    'country': airtable_data.get('country'),
                    'region': airtable_data.get('region'),
                    'timezone': airtable_data.get('timezone'),
                    'primary_leader': airtable_data.get('primary_leader'),
                    'co_leaders': airtable_data.get('co_leaders'),
                    'meeting_notes': airtable_data.get('meeting_notes'),
                    'club_applications_link': airtable_data.get('club_applications_link'),
                })
            )
            club.generate_join_code()

            db.session.add(club)
            db.session.commit()

            logger.info(f"Successfully created club '{club.name}' from Airtable data (ID: {club.id})")
            return club

        except Exception as e:
            logger.error(f"Error creating club from Airtable data: {str(e)}")
            logger.error(f"Exception type: {type(e).__name__}")
            logger.error(f"Airtable data that caused error: {airtable_data}")
            db.session.rollback()
            return None

    def update_club_in_airtable(self, airtable_record_id, fields):
        """Update a specific club record in Airtable"""
        if not self.api_token or not airtable_record_id:
            return False

        try:
            update_url = f"{self.clubs_base_url}/{airtable_record_id}"
            payload = {'fields': fields}

            response = requests.patch(update_url, headers=self.headers, json=payload)

            if response.status_code == 200:
                return True
            else:
                logger.error(f"Airtable update error: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            logger.error(f"Error updating Airtable record: {str(e)}")
            return False

    def send_email_verification(self, email):
        """Send email verification code to Airtable for automation with retry logic"""
        if not self.api_token:
            logger.error("Airtable API token not configured for email verification")
            return None

        verification_code = ''.join(secrets.choice(string.digits) for _ in range(5))

        max_retries = 3
        retry_count = 0

        while retry_count < max_retries:
            try:
                existing_params = {
                    'filterByFormula': f'AND({{Email}} = "{email}", {{Status}} = "Pending")'
                }

                existing_response = self._safe_request('GET', self.email_verification_url, headers=self.headers, params=existing_params, timeout=90)

                if existing_response.status_code == 200:
                    existing_data = existing_response.json()
                    existing_records = existing_data.get('records', [])

                    if existing_records:
                        record_id = existing_records[0]['id']
                        update_url = f"{self.email_verification_url}/{record_id}"

                        payload = {
                            'fields': {
                                'Code': verification_code,
                                'Status': 'Pending'
                            }
                        }

                        response = self._safe_request('PATCH', update_url, headers=self.headers, json=payload, timeout=90)
                    else:
                        payload = {
                            'records': [{
                                'fields': {
                                    'Email': email,
                                    'Code': verification_code,
                                    'Status': 'Pending'
                                }
                            }]
                        }

                        response = self._safe_request('POST', self.email_verification_url, headers=self.headers, json=payload, timeout=90)
                else:
                    payload = {
                        'records': [{
                            'fields': {
                                'Email': email,
                                'Code': verification_code,
                                'Status': 'Pending'
                            }
                        }]
                    }

                    response = self._safe_request('POST', self.email_verification_url, headers=self.headers, json=payload, timeout=90)

                if response.status_code in [200, 201]:
                    logger.info(f"Email verification code sent for {email}")
                    return verification_code
                else:
                    logger.error(f"Failed to send email verification: {response.status_code} - {response.text}")
                    return None

            except requests.exceptions.ReadTimeout as e:
                retry_count += 1
                logger.warning(f"Email verification timeout, attempt {retry_count}/{max_retries}: {str(e)}")
                if retry_count >= max_retries:
                    logger.error(f"Email verification failed after {max_retries} attempts due to timeout")
                    return None
                import time
                time.sleep(2 ** retry_count)  # Exponential backoff

            except Exception as e:
                logger.error(f"Exception sending email verification: {str(e)}")
                return None

        return None

    def verify_email_code(self, email, code):
        """Verify the email verification code"""
        if not self.api_token:
            logger.error("Airtable API token not configured for email verification")
            return False

        try:
            filter_params = {
                'filterByFormula': f'AND({{Email}} = "{email}", {{Code}} = "{code}", {{Status}} = "Pending")'
            }

            response = self._safe_request('GET', self.email_verification_url, headers=self.headers, params=filter_params, timeout=90)

            if response.status_code == 200:
                data = response.json()
                records = data.get('records', [])

                if records:
                    record_id = records[0]['id']
                    update_url = f"{self.email_verification_url}/{record_id}"

                    payload = {
                        'fields': {
                            'Status': 'Verified'
                        }
                    }

                    update_response = self._safe_request('PATCH', update_url, headers=self.headers, json=payload, timeout=90)

                    if update_response.status_code == 200:
                        logger.info(f"Email verification successful for {email}")
                        return True
                    else:
                        logger.error(f"Failed to update verification status: {update_response.status_code}")
                        return False
                else:
                    logger.warning(f"No pending verification found for {email} with code {code}")
                    return False
            else:
                logger.error(f"Error checking verification code: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            logger.error(f"Exception verifying email code: {str(e)}")
            return False

    def check_email_code(self, email, code):
        """Check if email verification code is valid without marking as verified"""
        if not self.api_token:
            logger.error("Airtable API token not configured for email verification")
            return False

        try:
            filter_params = {
                'filterByFormula': f'AND({{Email}} = "{email}", {{Code}} = "{code}", {{Status}} = "Pending")'
            }

            response = self._safe_request('GET', self.email_verification_url, headers=self.headers, params=filter_params, timeout=90)

            if response.status_code == 200:
                data = response.json()
                records = data.get('records', [])

                if records:
                    logger.info(f"Email verification code check successful for {email}")
                    return True
                else:
                    logger.warning(f"No pending verification found for {email} with code {code}")
                    return False
            else:
                logger.error(f"Error checking verification code: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            logger.error(f"Exception checking email code: {str(e)}")
            return False

    def check_recent_verification(self, email, max_age_minutes=5):
        """Check if there's a recent verified email verification for this email"""
        if not self.api_token:
            logger.error("Airtable API token not configured for email verification")
            return False

        try:
            from datetime import datetime, timedelta

            cutoff_time = datetime.utcnow() - timedelta(minutes=max_age_minutes)
            cutoff_time_iso = cutoff_time.isoformat() + 'Z'

            filter_params = {
                'filterByFormula': f'AND({{Email}} = "{email}", {{Status}} = "Verified", IS_AFTER({{Modified}}, "{cutoff_time_iso}"))'
            }

            response = self._safe_request('GET', self.email_verification_url, headers=self.headers, params=filter_params, timeout=90)

            if response.status_code == 200:
                data = response.json()
                records = data.get('records', [])

                if records:
                    logger.info(f"Recent verification found for {email}")
                    return True
                else:
                    logger.warning(f"No recent verification found for {email}")
                    return False
            else:
                logger.error(f"Error checking recent verification: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            logger.error(f"Exception checking recent verification: {str(e)}")
            return False

    def sync_all_clubs_with_airtable(self):
        """Sync all clubs with Airtable data"""
        try:
            airtable_clubs = self.get_all_clubs_from_airtable()

            created_count = 0
            updated_count = 0

            for airtable_club in airtable_clubs:
                leader_email = airtable_club.get('leader_email')
                if not leader_email:
                    continue

                leader = User.query.filter_by(email=leader_email).first()
                existing_club = None

                if leader:
                    existing_club = Club.query.filter_by(leader_id=leader.id).first()

                if existing_club:
                    if self.sync_club_with_airtable(existing_club.id, airtable_club):
                        updated_count += 1
                else:
                    new_club = self.create_club_from_airtable(airtable_club)
                    if new_club:
                        created_count += 1

            return {
                'success': True,
                'created': created_count,
                'updated': updated_count,
                'total_airtable_clubs': len(airtable_clubs)
            }

        except Exception as e:
            logger.error(f"Error syncing all clubs with Airtable: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }

    def submit_project_data(self, submission_data):
        """Submit project submission data to Airtable"""
        if not self.api_token:
            logger.error("AIRTABLE: API token not configured")
            return None

        try:
            project_table_name = urllib.parse.quote('YSWS Project Submission')
            project_url = f'https://api.airtable.com/v0/{self.base_id}/{project_table_name}'

            logger.info(f"AIRTABLE: Submitting to URL: {project_url}")

            fields = {
                'Address (Line 1)': submission_data.get('address_1', ''),
                'Birthday': submission_data.get('birthday', ''),
                'City': submission_data.get('city', ''),
                'Club Name': submission_data.get('club_name', ''),
                'Code URL': submission_data.get('github_url', ''),
                'Country': submission_data.get('country', ''),
                'Description': submission_data.get('project_description', ''),
                'Email': submission_data.get('email', ''),
                'First Name': submission_data.get('first_name', ''),
                'GitHub Username': submission_data.get('github_username', ''),
                'Hackatime Project': submission_data.get('project_name', ''),
                'Hours': float(str(submission_data.get('project_hours', '0')).strip()),
                'How can we improve?': submission_data.get('improve', ''),
                'How did you hear about this?': 'Through Club Leader Dashboard',
                'Last Name': submission_data.get('last_name', ''),
                'Leader Email': submission_data.get('leader_email', ''),
                'Playable URL': submission_data.get('live_url', ''),
                'State / Province': submission_data.get('state', ''),
                'Status': 'Pending',
                'What are we doing well?': submission_data.get('doing_well', ''),
                'ZIP / Postal Code': submission_data.get('zip', '')
            }

            fields = {k: v for k, v in fields.items() if v not in [None, '', []]}

            logger.info(f"AIRTABLE: Submitting fields: {list(fields.keys())}")
            logger.info(f"AIRTABLE: Project name: {fields.get('Hackatime Project', 'NOT_FOUND')}")
            logger.info(f"AIRTABLE: Hours: {fields.get('Hours', 'NOT_FOUND')}")

            payload = {'records': [{'fields': fields}]}

            response = self._safe_request('POST', project_url, headers=self.headers, json=payload)

            logger.info(f"AIRTABLE: Response status: {response.status_code}")
            if response.status_code not in [200, 201]:
                logger.error(f"AIRTABLE: Submission failed: {response.text}")
                return None

            result = response.json()
            logger.info(f"AIRTABLE: Successfully submitted project! Record ID: {result.get('records', [{}])[0].get('id', 'UNKNOWN')}")
            return result

        except Exception as e:
            logger.error(f"AIRTABLE: Exception in submit_project_data: {str(e)}")
            return None

    def get_ysws_project_submissions(self):
        """Get all YSWS project submissions from Airtable"""
        if not self.api_token:
            logger.error("AIRTABLE: API token not configured")
            return []

        try:
            project_table_name = urllib.parse.quote('YSWS Project Submission')
            project_url = f'https://api.airtable.com/v0/{self.base_id}/{project_table_name}'

            all_records = []
            offset = None

            while True:
                params = {}
                if offset:
                    params['offset'] = offset

                response = self._safe_request('GET', project_url, headers=self.headers, params=params)

                if response.status_code != 200:
                    logger.error(f"AIRTABLE: Failed to fetch project submissions: {response.text}")
                    break

                data = response.json()
                records = data.get('records', [])
                all_records.extend(records)

                offset = data.get('offset')
                if not offset:
                    break

            submissions = []
            for record in all_records:
                fields = record.get('fields', {})
                submission = {
                    'id': record.get('id'),
                    'firstName': fields.get('First Name', ''),
                    'lastName': fields.get('Last Name', ''),
                    'email': fields.get('Email', ''),
                    'age': fields.get('Age', ''),
                    'codeUrl': fields.get('Code URL', ''),
                    'playableUrl': fields.get('Playable URL', ''),
                    'description': fields.get('Description', ''),
                    'githubUsername': fields.get('GitHub Username', ''),
                    'addressLine1': fields.get('Address (Line 1)', ''),
                    'addressLine2': fields.get('Address (Line 2)', ''),
                    'city': fields.get('City', ''),
                    'country': fields.get('Country', ''),
                    'zipCode': fields.get('ZIP / Postal Code', ''),
                    'birthday': fields.get('Birthday', ''),
                    'hackatimeProject': fields.get('Hackatime Project', ''),
                    'hours': fields.get('Hours', ''),
                    'grantAmount': fields.get('Grant Amount Override') or fields.get('Grant Amount', ''),
                    'clubName': fields.get('Club Name', ''),
                    'leaderEmail': fields.get('Leader Email', ''),
                    'status': fields.get('Status', 'Pending'),
                    'autoReviewStatus': fields.get('Auto Review Status', ''),
                    'decisionReason': fields.get('Decision Reason', ''),
                    'howDidYouHear': fields.get('How did you hear about this?', ''),
                    'whatAreWeDoingWell': fields.get('What are we doing well?', ''),
                    'howCanWeImprove': fields.get('How can we improve?', ''),
                    'screenshot': fields.get('Screenshot', ''),
                    'grantOverrideReason': fields.get('Grant Override Reason', ''),
                    'createdTime': record.get('createdTime', '')
                }

                if isinstance(submission['screenshot'], list) and len(submission['screenshot']) > 0:
                    submission['screenshot'] = submission['screenshot'][0].get('url', '')
                elif not isinstance(submission['screenshot'], str):
                    submission['screenshot'] = ''

                submissions.append(submission)

            logger.info(f"AIRTABLE: Fetched {len(submissions)} project submissions")
            return submissions

        except Exception as e:
            logger.error(f"AIRTABLE: Exception in get_ysws_project_submissions: {str(e)}")
            return []

    def update_ysws_project_submission(self, record_id, fields):
        """Update a YSWS project submission in Airtable"""
        if not self.api_token or not record_id:
            logger.error("AIRTABLE: API token not configured or no record ID provided")
            return False

        try:
            project_table_name = urllib.parse.quote('YSWS Project Submission')
            update_url = f'https://api.airtable.com/v0/{self.base_id}/{project_table_name}/{record_id}'

            allowed_fields = {
                'Status', 'Decision Reason', 'Grant Amount Override', 'Auto Review Status', 'Grant Override Reason'
            }

            update_fields = {k: v for k, v in fields.items() if k in allowed_fields}

            payload = {'fields': update_fields}

            response = self._safe_request('PATCH', update_url, headers=self.headers, json=payload)

            if response.status_code == 200:
                logger.info(f"AIRTABLE: Successfully updated project submission {record_id}")
                return True
            else:
                logger.error(f"AIRTABLE: Failed to update project submission: {response.text}")
                return False

        except Exception as e:
            logger.error(f"AIRTABLE: Exception in update_ysws_project_submission: {str(e)}")
            return False

    def delete_ysws_project_submission(self, record_id):
        """Delete a YSWS project submission from Airtable"""
        if not self.api_token or not record_id:
            logger.error("AIRTABLE: API token not configured or no record ID provided")
            return False

        try:
            project_table_name = urllib.parse.quote('YSWS Project Submission')
            delete_url = f'https://api.airtable.com/v0/{self.base_id}/{project_table_name}/{record_id}'

            response = self._safe_request('DELETE', delete_url, headers=self.headers)

            if response.status_code == 200:
                logger.info(f"AIRTABLE: Successfully deleted project submission {record_id}")
                return True
            else:
                logger.error(f"AIRTABLE: Failed to delete project submission: {response.text}")
                return False

        except Exception as e:
            logger.error(f"AIRTABLE: Exception in delete_ysws_project_submission: {str(e)}")
            return False

    def submit_order(self, order_data):
        """Submit order to Orders table"""
        if not self.api_token:
            return None

        shop_base_id = 'app7OFpfZceddfK17'
        orders_table_name = urllib.parse.quote('Orders')
        orders_url = f'https://api.airtable.com/v0/{shop_base_id}/{orders_table_name}'

        fields = {
            'Club Name': order_data.get('club_name', ''),
            'Leader First Name': order_data.get('leader_first_name', ''),
            'Leader Last Name': order_data.get('leader_last_name', ''),
            'Leader Email': order_data.get('leader_email', ''),
            'Club Member Amount': order_data.get('club_member_amount', 0),
            'Product(s)': order_data.get('products', ''),
            'Total Estimated Cost': order_data.get('total_estimated_cost', 0),
            'Delivery Address Line 1': order_data.get('delivery_address_line_1', ''),
            'Delivery Address Line 2': order_data.get('delivery_address_line_2', ''),
            'City': order_data.get('delivery_city', ''),
            'Delivery ZIP/Postal Code': order_data.get('delivery_zip', ''),
            'Delivery State/Area': order_data.get('delivery_state', ''),
            'Delivery Country': order_data.get('delivery_country', ''),
            'Special Notes': order_data.get('special_notes', ''),
            'Usage Reason': order_data.get('usage_reason', ''),
            'Order Sources': order_data.get('order_sources', []),
            'Shipment Status': 'Pending'
        }

        payload = {'records': [{'fields': fields}]}

        try:
            response = requests.post(orders_url, headers=self.headers, json=payload)
            logger.debug(f"Airtable Orders response status: {response.status_code}")
            logger.debug(f"Airtable Orders response body: {response.text}")
            if response.status_code in [200, 201]:
                return response.json()
            else:
                logger.error(f"Airtable Orders error: {response.text}")
                return None
        except Exception as e:
            logger.error(f"Exception submitting to Airtable Orders: {str(e)}")
            return None

    def get_orders_for_club(self, club_name):
        """Get all orders for a specific club"""
        if not self.api_token:
            return []

        shop_base_id = 'app7OFpfZceddfK17'
        orders_table_name = urllib.parse.quote('Orders')
        orders_url = f'https://api.airtable.com/v0/{shop_base_id}/{orders_table_name}'

        try:
            params = {
                'filterByFormula': f"{{Club Name}} = '{club_name}'"
            }

            response = requests.get(orders_url, headers=self.headers, params=params)
            if response.status_code == 200:
                data = response.json()
                records = data.get('records', [])

                orders = []
                for record in records:
                    fields = record.get('fields', {})
                    orders.append({
                        'id': record['id'],
                        'club_name': fields.get('Club Name', ''),
                        'leader_first_name': fields.get('Leader First Name', ''),
                        'leader_last_name': fields.get('Leader Last Name', ''),
                        'leader_email': fields.get('Leader Email', ''),
                        'club_member_amount': fields.get('Club Member Amount', 0),
                        'products': fields.get('Product(s)', ''),
                        'total_estimated_cost': fields.get('Total Estimated Cost', 0),
                        'delivery_address_line_1': fields.get('Delivery Address Line 1', ''),
                        'delivery_address_line_2': fields.get('Delivery Address Line 2', ''),
                        'delivery_city': fields.get('City', ''),
                        'delivery_zip': fields.get('Delivery ZIP/Postal Code', ''),
                        'delivery_state': fields.get('Delivery State/Area', ''),
                        'delivery_country': fields.get('Delivery Country', ''),
                        'special_notes': fields.get('Special Notes', ''),
                        'usage_reason': fields.get('Usage Reason', ''),
                        'order_sources': fields.get('Order Sources', []),
                        'shipment_status': fields.get('Shipment Status', 'Pending'),
                        'created_time': record.get('createdTime', '')
                    })

                return orders
            else:
                logger.error(f"Failed to fetch orders: {response.status_code} - {response.text}")
                return []
        except Exception as e:
            logger.error(f"Error fetching orders for club {club_name}: {str(e)}")
            return []

    def get_all_orders(self):
        """Get all orders for admin review"""
        if not self.api_token:
            return []

        shop_base_id = 'app7OFpfZceddfK17'
        orders_table_name = urllib.parse.quote('Orders')
        orders_url = f'https://api.airtable.com/v0/{shop_base_id}/{orders_table_name}'

        try:
            all_orders = []
            offset = None

            while True:
                params = {}
                if offset:
                    params['offset'] = offset

                response = requests.get(orders_url, headers=self.headers, params=params)
                if response.status_code == 200:
                    data = response.json()
                    records = data.get('records', [])

                    for record in records:
                        fields = record.get('fields', {})
                        all_orders.append({
                            'id': record['id'],
                            'club_name': fields.get('Club Name', ''),
                            'leader_first_name': fields.get('Leader First Name', ''),
                            'leader_last_name': fields.get('Leader Last Name', ''),
                            'leader_email': fields.get('Leader Email', ''),
                            'club_member_amount': fields.get('Club Member Amount', 0),
                            'products': fields.get('Product(s)', ''),
                            'total_estimated_cost': fields.get('Total Estimated Cost', 0),
                            'delivery_address_line_1': fields.get('Delivery Address Line 1', ''),
                            'delivery_address_line_2': fields.get('Delivery Address Line 2', ''),
                            'delivery_city': fields.get('City', ''),
                            'delivery_zip': fields.get('Delivery ZIP/Postal Code', ''),
                            'delivery_state': fields.get('Delivery State/Area', ''),
                            'delivery_country': fields.get('Delivery Country', ''),
                            'special_notes': fields.get('Special Notes', ''),
                            'usage_reason': fields.get('Usage Reason', ''),
                            'order_sources': fields.get('Order Sources', []),
                            'shipment_status': fields.get('Shipment Status', 'Pending'),
                            'reviewer_reason': fields.get('Reviewer Reason', ''),
                            'created_time': record.get('createdTime', '')
                        })

                    offset = data.get('offset')
                    if not offset:
                        break
                else:
                    logger.error(f"Failed to fetch all orders: {response.status_code} - {response.text}")
                    break

            return all_orders
        except Exception as e:
            logger.error(f"Error fetching all orders: {str(e)}")
            return []

    def update_order_status(self, order_id, status, reviewer_reason):
        """Update order status and reviewer reason"""
        if not self.api_token:
            return False

        shop_base_id = 'app7OFpfZceddfK17'
        orders_table_name = urllib.parse.quote('Orders')
        update_url = f'https://api.airtable.com/v0/{shop_base_id}/{orders_table_name}/{order_id}'

        fields = {
            'Shipment Status': status,
            'Reviewer Reason': reviewer_reason
        }

        payload = {'fields': fields}

        try:
            response = requests.patch(update_url, headers=self.headers, json=payload)
            logger.debug(f"Airtable order update response status: {response.status_code}")
            logger.debug(f"Airtable order update response body: {response.text}")
            if response.status_code == 200:
                return True
            else:
                logger.error(f"Airtable order update error: {response.text}")
                return False
        except Exception as e:
            logger.error(f"Exception updating order status: {str(e)}")
            return False

    def delete_order(self, order_id):
        """Delete an order record"""
        if not self.api_token:
            return False

        shop_base_id = 'app7OFpfZceddfK17'
        orders_table_name = urllib.parse.quote('Orders')
        delete_url = f'https://api.airtable.com/v0/{shop_base_id}/{orders_table_name}/{order_id}'

        try:
            response = requests.delete(delete_url, headers=self.headers)
            logger.debug(f"Airtable order delete response status: {response.status_code}")
            logger.debug(f"Airtable order delete response body: {response.text}")
            if response.status_code == 200:
                return True
            else:
                logger.error(f"Airtable order delete error: {response.text}")
                return False
        except Exception as e:
            logger.error(f"Exception deleting order: {str(e)}")
            return False

    def log_gallery_post(self, post_title, description, photos, club_name, author_username):
        """Log gallery post to Airtable Gallery table"""
        if not self.api_token:
            logger.error("AIRTABLE: API token not configured for gallery logging")
            return False

        try:
            gallery_base_id = 'app7OFpfZceddfK17'  # Base ID provided by user
            gallery_table_name = urllib.parse.quote('Gallary')  # Table name provided by user (note the spelling)
            gallery_url = f'https://api.airtable.com/v0/{gallery_base_id}/{gallery_table_name}'

            photos_formatted = ', '.join(photos) if photos else ''

            fields = {
                'Post Title': post_title,
                'Description': description,
                'Photos': photos_formatted,
                'Club Name': club_name
            }

            payload = {'fields': fields}

            logger.info(f"AIRTABLE: Logging gallery post to {gallery_url}")
            logger.debug(f"AIRTABLE: Gallery post payload: {payload}")

            response = self._safe_request('POST', gallery_url, headers=self.headers, json=payload)

            logger.info(f"AIRTABLE: Gallery post response status: {response.status_code}")

            if response.status_code == 200:
                result = response.json()
                logger.info(f"AIRTABLE: Successfully logged gallery post! Record ID: {result.get('id', 'UNKNOWN')}")
                return True
            else:
                logger.error(f"AIRTABLE: Gallery post logging failed: {response.text}")
                return False

        except Exception as e:
            logger.error(f"AIRTABLE: Exception in log_gallery_post: {str(e)}")
            return False

    def get_pizza_grants(self):
        """Get all pizza grants from Grants table"""
        if not self.api_token:
            logger.error("AIRTABLE: API token not configured")
            return []

        try:
            grants_table_name = urllib.parse.quote('Grants')
            grants_url = f'https://api.airtable.com/v0/{self.base_id}/{grants_table_name}'

            all_records = []
            offset = None

            while True:
                params = {}
                if offset:
                    params['offset'] = offset

                response = self._safe_request('GET', grants_url, headers=self.headers, params=params)

                if response.status_code != 200:
                    logger.error(f"AIRTABLE: Failed to fetch pizza grants: {response.text}")
                    break

                data = response.json()
                records = data.get('records', [])
                all_records.extend(records)

                offset = data.get('offset')
                if not offset:
                    break

            grants = []
            for record in all_records:
                fields = record.get('fields', {})
                grants.append({
                    'id': record.get('id'),
                    'club': fields.get('Club', ''),
                    'email': fields.get('Email', ''),
                    'status': fields.get('Status', ''),
                    'grant_amount': fields.get('Grant Amount', 0),
                    'grant_type': fields.get('Grant Type', ''),
                    'address': fields.get('Address', ''),
                    'order_id': fields.get('Order ID', ''),
                    'created_time': record.get('createdTime', '')
                })

            logger.info(f"AIRTABLE: Fetched {len(grants)} pizza grants")
            return grants

        except Exception as e:
            logger.error(f"AIRTABLE: Exception in get_pizza_grants: {str(e)}")
            return []

    def update_pizza_grant(self, grant_id, status, notes, reviewer_username):
        """Update a pizza grant status"""
        if not self.api_token or not grant_id:
            logger.error("AIRTABLE: API token not configured or no grant ID provided")
            return False

        try:
            grants_table_name = urllib.parse.quote('Grants')
            update_url = f'https://api.airtable.com/v0/{self.base_id}/{grants_table_name}/{grant_id}'

            fields = {
                'Status': status.capitalize(),
                'Reviewer': reviewer_username
            }

            if notes:
                fields['Notes'] = notes

            payload = {'fields': fields}

            response = self._safe_request('PATCH', update_url, headers=self.headers, json=payload)

            if response.status_code == 200:
                logger.info(f"AIRTABLE: Successfully updated pizza grant {grant_id}")
                return True
            else:
                logger.error(f"AIRTABLE: Failed to update pizza grant: {response.text}")
                return False

        except Exception as e:
            logger.error(f"AIRTABLE: Exception in update_pizza_grant: {str(e)}")
            return False

    def delete_pizza_grant(self, grant_id):
        """Delete a pizza grant from Grants table"""
        if not self.api_token or not grant_id:
            logger.error("AIRTABLE: API token not configured or no grant ID provided")
            return False

        try:
            grants_table_name = urllib.parse.quote('Grants')
            delete_url = f'https://api.airtable.com/v0/{self.base_id}/{grants_table_name}/{grant_id}'

            response = self._safe_request('DELETE', delete_url, headers=self.headers)

            if response.status_code == 200:
                logger.info(f"AIRTABLE: Successfully deleted pizza grant {grant_id}")
                return True
            else:
                logger.error(f"AIRTABLE: Failed to delete pizza grant: {response.text}")
                return False

        except Exception as e:
            logger.error(f"AIRTABLE: Exception in delete_pizza_grant: {str(e)}")
            return False

    def get_all_clubs(self):
        """Fetch all clubs from Airtable Clubs Dashboard table"""
        if not self.api_token:
            logger.error("Airtable API token not configured")
            return []

        if not self.clubs_base_id or not self.clubs_table_id:
            logger.error("Airtable clubs base ID or table ID not configured")
            return []

        try:
            clubs = []
            offset = None

            while True:
                params = {'pageSize': 100}
                if offset:
                    params['offset'] = offset

                response = self._safe_request('GET', self.clubs_base_url, headers=self.headers, params=params)

                if response.status_code == 200:
                    data = response.json()
                    records = data.get('records', [])

                    for record in records:
                        fields = record.get('fields', {})
                        # Leader Email is a lookup field that returns an array
                        leader_email_field = fields.get("Leader Email", [])
                        leader_emails = leader_email_field[0] if isinstance(leader_email_field, list) and leader_email_field else (leader_email_field if isinstance(leader_email_field, str) else '')

                        club_data = {
                            'airtable_id': record.get('id'),
                            'name': fields.get('Club Name', ''),
                            'location': fields.get('Venue Name', '') or fields.get('Venue City', ''),
                            'leader_emails': leader_emails,
                            'suspended': fields.get('Suspension Status', False),
                            'is_airtable_only': True,  # Mark as Airtable-only
                            'team_notes': fields.get('Team Notes', '').strip() if fields.get('Team Notes') else '',
                        }
                        clubs.append(club_data)

                    # Check if there are more pages
                    offset = data.get('offset')
                    if not offset:
                        break
                else:
                    logger.error(f"Failed to fetch clubs from Airtable: {response.status_code} - {response.text}")
                    break

            logger.info(f"Fetched {len(clubs)} clubs from Airtable")
            return clubs

        except Exception as e:
            logger.error(f"Exception fetching clubs from Airtable: {str(e)}")
            return []

    def _get_club_airtable_id_by_name(self, club_name):
        """Helper: Get club's Airtable ID by searching for its name
        Returns: (airtable_id, club_fields) or (None, None) if not found
        """
        try:
            logger.info(f"🔍 Searching for club by name: {club_name}")
            all_clubs = self.get_all_clubs()

            club_name_lower = club_name.lower().strip()
            for club in all_clubs:
                if club.get('name', '').lower().strip() == club_name_lower:
                    airtable_id = club.get('airtable_id')
                    logger.info(f"✅ Found club with ID: {airtable_id}")

                    # Fetch full club details
                    club_url = f'{self.clubs_base_url}/{airtable_id}'
                    response = self._safe_request('GET', club_url, headers=self.headers)

                    if response.status_code == 200:
                        club_data = response.json()
                        return (airtable_id, club_data.get('fields', {}))

            logger.warning(f"⚠️  Could not find club '{club_name}' in Airtable")
            return (None, None)

        except Exception as e:
            logger.error(f"Exception searching for club by name: {str(e)}")
            return (None, None)

    def update_club_suspension(self, airtable_id, suspended, club_name=None):
        """Update club suspension status in Airtable

        Args:
            airtable_id: The Airtable record ID
            suspended: Boolean suspension status
            club_name: Optional club name for fallback search
        """
        if not self.api_token:
            logger.error("Airtable API token not configured")
            return False

        if not self.clubs_base_id or not self.clubs_table_id or not airtable_id:
            logger.error(f"Missing required parameters for updating club suspension - Base: {self.clubs_base_id}, Table: {self.clubs_table_id}, ID: {airtable_id}")
            return False

        try:
            update_url = f'{self.clubs_base_url}/{airtable_id}'

            payload = {
                'fields': {
                    'Suspension Status': suspended
                }
            }

            logger.info(f"Attempting to update club suspension in Airtable: {airtable_id} to {suspended}")
            logger.debug(f"Update URL: {update_url}")
            logger.debug(f"Payload: {payload}")

            response = self._safe_request('PATCH', update_url, headers=self.headers, json=payload)

            if response.status_code == 200:
                logger.info(f"✅ Successfully updated club suspension in Airtable: {airtable_id} - Suspended: {suspended}")
                return True
            elif response.status_code in [403, 404] and club_name:
                # Fallback: Try finding by name
                logger.warning(f"⚠️  Could not update by ID, trying fallback search by name")
                new_id, _ = self._get_club_airtable_id_by_name(club_name)

                if new_id:
                    logger.info(f"💡 Found new ID: {new_id}, retrying update")
                    return self.update_club_suspension(new_id, suspended, club_name=None)  # Retry without fallback
                else:
                    logger.error(f"❌ Could not find club by name for fallback")
                    return False
            else:
                logger.error(f"❌ Failed to update club suspension: {response.status_code} - {response.text}")
                logger.error(f"Request was to: {update_url} with payload: {payload}")
                return False

        except Exception as e:
            logger.error(f"Exception updating club suspension: {str(e)}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            return False

    def mark_club_onboarded(self, airtable_id, club_name=None):
        """Mark a club as onboarded to dashboard in Airtable

        Args:
            airtable_id: The Airtable record ID
            club_name: Optional club name for fallback search
        """
        if not self.api_token:
            logger.error("Airtable API token not configured")
            return False

        if not self.clubs_base_id or not self.clubs_table_id or not airtable_id:
            logger.error("Missing required parameters for marking club as onboarded")
            return False

        try:
            update_url = f'{self.clubs_base_url}/{airtable_id}'

            payload = {
                'fields': {
                    'Onboarded to Dashboard': True
                }
            }

            response = self._safe_request('PATCH', update_url, headers=self.headers, json=payload)

            if response.status_code == 200:
                logger.info(f"✅ Successfully marked club as onboarded in Airtable: {airtable_id}")
                return True
            elif response.status_code in [403, 404] and club_name:
                # Fallback: Try finding by name
                logger.warning(f"⚠️  Could not mark onboarded by ID, trying fallback search")
                new_id, _ = self._get_club_airtable_id_by_name(club_name)

                if new_id:
                    logger.info(f"💡 Found new ID: {new_id}, retrying")
                    return self.mark_club_onboarded(new_id, club_name=None)  # Retry without fallback
                else:
                    logger.error(f"❌ Could not find club by name for fallback")
                    return False
            else:
                logger.error(f"❌ Failed to mark club as onboarded: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            logger.error(f"Exception marking club as onboarded: {str(e)}")
            return False

    def unmark_club_onboarded(self, airtable_id, club_name=None):
        """Remove onboarded status from a club in Airtable
        
        Args:
            airtable_id: The Airtable record ID
            club_name: Optional club name for fallback search
        """
        if not self.api_token:
            logger.error("Airtable API token not configured")
            return False
        
        if not self.clubs_base_id or not self.clubs_table_id or not airtable_id:
            logger.error("Missing required parameters for unmarking club as onboarded")
            return False
        
        try:
            update_url = f'{self.clubs_base_url}/{airtable_id}'
            
            payload = {
                'fields': {
                    'Onboarded to Dashboard': False
                }
            }
            
            response = self._safe_request('PATCH', update_url, headers=self.headers, json=payload)
            
            if response.status_code == 200:
                logger.info(f"✅ Successfully unmarked club as onboarded in Airtable: {airtable_id}")
                return True
            elif response.status_code in [403, 404] and club_name:
                # Fallback: Try finding by name
                logger.warning(f"⚠️  Could not unmark onboarded by ID, trying fallback search")
                new_id, _ = self._get_club_airtable_id_by_name(club_name)
                
                if new_id:
                    logger.info(f"💡 Found new ID: {new_id}, retrying")
                    return self.unmark_club_onboarded(new_id, club_name=None)  # Retry without fallback
                else:
                    logger.error(f"❌ Could not find club by name for fallback")
                    return False
            else:
                logger.error(f"❌ Failed to unmark club as onboarded: {response.status_code} - {response.text}")
                return False
        
        except Exception as e:
            logger.error(f"Exception unmarking club as onboarded: {str(e)}")
            return False

    def update_club_leader_email_direct(self, club_airtable_id, new_email, club_name=None):
        """Update the email of the leader linked to a specific club
        This finds the club's linked leader and updates that leader's email directly.
        NEVER creates new leaders - only updates existing ones.

        Args:
            club_airtable_id: The Airtable record ID of the club
            new_email: The new email to set for the leader
            club_name: Optional club name to search by if ID doesn't work
        """
        if not self.api_token:
            logger.error("Airtable API token not configured")
            return False

        if not club_airtable_id:
            logger.error("No club airtable_id provided")
            return False

        try:
            # Step 1: Get the club record to find its linked leader
            club_url = f'{self.clubs_base_url}/{club_airtable_id}'
            logger.info(f"🔍 Fetching club {club_airtable_id} to find linked leader")

            club_response = self._safe_request('GET', club_url, headers=self.headers)

            if club_response.status_code != 200:
                logger.warning(f"⚠️  Could not fetch club by ID: {club_response.status_code} - {club_response.text}")

                # If we have a club name, try searching for it
                if club_name:
                    logger.info(f"🔍 Trying to find club by name: {club_name}")
                    result = self._update_leader_email_by_club_search(club_name, new_email)
                    if isinstance(result, tuple):
                        success, new_id = result
                        if success and new_id:
                            logger.info(f"💡 Hint: Update club's airtable_data to use new ID: {new_id}")
                        return success
                    return result
                else:
                    logger.error(f"❌ No club name provided for fallback search")
                    return False

            club_data = club_response.json()
            club_fields = club_data.get('fields', {})

            # Step 2: Get the Leader field (linked record to Leaders table)
            leader_ids = club_fields.get('Leader', [])

            if not leader_ids:
                logger.error(f"❌ Club {club_airtable_id} has no leader linked in Airtable")
                return False

            leader_id = leader_ids[0]  # Get the first/primary leader
            logger.info(f"✅ Found linked leader: {leader_id}")

            # Step 3: Get the current leader's email
            leader_url = f'{self.leaders_base_url}/{leader_id}'
            leader_response = self._safe_request('GET', leader_url, headers=self.headers)

            if leader_response.status_code != 200:
                logger.error(f"Failed to fetch leader from Airtable: {leader_response.status_code} - {leader_response.text}")
                return False

            leader_data = leader_response.json()
            current_email = leader_data.get('fields', {}).get('Email', '')

            logger.info(f"📧 Current leader email in Airtable: {current_email}")
            logger.info(f"📧 New email from dashboard: {new_email}")

            # Step 4: Check if emails match
            if current_email == new_email:
                logger.info(f"✅ Emails already match, no update needed")
                return True

            # Step 5: Update the leader's email in Airtable
            update_payload = {
                'fields': {
                    'Email': new_email
                }
            }

            logger.info(f"📝 Updating leader {leader_id} email from '{current_email}' to '{new_email}'")
            update_response = self._safe_request('PATCH', leader_url, headers=self.headers, json=update_payload)

            if update_response.status_code == 200:
                logger.info(f"✅ Successfully updated leader email in Airtable")
                return True
            else:
                logger.error(f"❌ Failed to update leader email: {update_response.status_code} - {update_response.text}")
                return False

        except Exception as e:
            logger.error(f"Exception updating club leader email directly: {str(e)}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            return False

    def _update_leader_email_by_club_search(self, club_name, new_email):
        """Helper method: Find club by name and update its leader's email

        Returns:
            tuple: (success: bool, new_airtable_id: str or None)
        """
        try:
            # Search for club by name
            logger.info(f"🔍 Searching all clubs for '{club_name}'")
            all_clubs = self.get_all_clubs()
            matching_club = None

            club_name_lower = club_name.lower().strip()
            for club in all_clubs:
                if club.get('name', '').lower().strip() == club_name_lower:
                    matching_club = club
                    break

            if not matching_club:
                logger.error(f"❌ Could not find club '{club_name}' in Airtable")
                return (False, None)

            club_airtable_id = matching_club.get('airtable_id')
            logger.info(f"✅ Found club in Airtable with NEW ID: {club_airtable_id}")

            # Now fetch the full club record and update leader
            club_url = f'{self.clubs_base_url}/{club_airtable_id}'
            club_response = self._safe_request('GET', club_url, headers=self.headers)

            if club_response.status_code != 200:
                logger.error(f"Failed to fetch club details: {club_response.status_code}")
                return False

            club_data = club_response.json()
            club_fields = club_data.get('fields', {})
            leader_ids = club_fields.get('Leader', [])

            if not leader_ids:
                logger.error(f"❌ Club has no leader linked in Airtable")
                return False

            # Update the leader's email
            leader_id = leader_ids[0]
            leader_url = f'{self.leaders_base_url}/{leader_id}'

            update_payload = {
                'fields': {
                    'Email': new_email
                }
            }

            logger.info(f"📝 Updating leader {leader_id} email to {new_email}")
            update_response = self._safe_request('PATCH', leader_url, headers=self.headers, json=update_payload)

            if update_response.status_code == 200:
                logger.info(f"✅ Successfully updated leader email")
                return (True, club_airtable_id)  # Return the new ID so caller can update it
            else:
                logger.error(f"❌ Failed to update leader email: {update_response.status_code} - {update_response.text}")
                return (False, club_airtable_id)

        except Exception as e:
            logger.error(f"Exception in _update_leader_email_by_club_search: {str(e)}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            return (False, None)

    def update_leader_email_by_search(self, old_email, new_email):
        """Update leader email in Leaders table by searching for old email
        This is more reliable than trying to access club records.
        """
        if not self.api_token:
            logger.error("Airtable API token not configured")
            return False

        # If emails are the same, no update needed
        if old_email == new_email:
            logger.info(f"Old and new email are the same ({old_email}), no update needed")
            return True

        try:
            # Properly escape email for Airtable formula (double quotes need escaping)
            escaped_old_email = old_email.replace('"', '\\"')
            escaped_new_email = new_email.replace('"', '\\"')

            # Search for leader by old email in Leaders table
            filter_params = {
                'filterByFormula': f'{{Email}} = "{escaped_old_email}"'
            }

            logger.info(f"🔍 Searching for leader with email: {old_email}")
            response = self._safe_request('GET', self.leaders_base_url, headers=self.headers, params=filter_params)

            if response.status_code != 200:
                logger.error(f"Failed to search for leader: {response.status_code} - {response.text}")
                return False

            data = response.json()
            records = data.get('records', [])

            if not records:
                logger.warning(f"⚠️  No leader found with email {old_email} in Airtable Leaders table")
                logger.warning(f"⚠️  This means the leader doesn't exist in Airtable yet")

                # Check if new email already exists (to avoid duplicates)
                check_filter = {
                    'filterByFormula': f'{{Email}} = "{escaped_new_email}"'
                }
                check_response = self._safe_request('GET', self.leaders_base_url, headers=self.headers, params=check_filter)

                if check_response.status_code == 200:
                    existing = check_response.json().get('records', [])
                    if existing:
                        logger.info(f"✅ Leader with new email {new_email} already exists, no action needed")
                        return True

                # Create new leader with new email
                logger.info(f"➕ Creating new leader with email: {new_email}")
                leader_record = self._find_or_create_leader(new_email)
                return leader_record is not None

            # Found the leader(s), update their email
            logger.info(f"✅ Found {len(records)} leader record(s) with email {old_email}")

            updated_count = 0
            for record in records:
                leader_id = record.get('id')
                leader_url = f'{self.leaders_base_url}/{leader_id}'

                update_payload = {
                    'fields': {
                        'Email': new_email
                    }
                }

                logger.info(f"📝 Updating leader {leader_id} email from {old_email} to {new_email}")
                update_response = self._safe_request('PATCH', leader_url, headers=self.headers, json=update_payload)

                if update_response.status_code == 200:
                    logger.info(f"✅ Successfully updated leader {leader_id} email")
                    updated_count += 1
                else:
                    logger.error(f"❌ Failed to update leader {leader_id}: {update_response.status_code} - {update_response.text}")

            if updated_count > 0:
                logger.info(f"✅ Successfully updated {updated_count} leader record(s) in Airtable: {old_email} -> {new_email}")
                return True
            else:
                return False

        except Exception as e:
            logger.error(f"Exception updating leader email by search: {str(e)}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            return False

    def update_club_leader_email(self, airtable_id, email):
        """Update club leader email in Airtable
        Note: In the new base, Leader Email is a lookup field from the Leaders table.
        This method updates the email in the Leaders table instead of modifying the linked record.
        """
        if not self.api_token:
            logger.error("Airtable API token not configured")
            return False

        if not self.clubs_base_id or not self.clubs_table_id or not airtable_id:
            logger.error("Missing required parameters for updating club leader email")
            return False

        try:
            # First, get the club to find its current leader
            club_url = f'{self.clubs_base_url}/{airtable_id}'
            club_response = self._safe_request('GET', club_url, headers=self.headers)

            if club_response.status_code != 200:
                logger.error(f"Failed to fetch club from Airtable: {club_response.status_code} - {club_response.text}")
                return False

            club_data = club_response.json()
            club_fields = club_data.get('fields', {})

            # Get the current leader record IDs (it's an array)
            current_leader_ids = club_fields.get('Leader', [])

            if not current_leader_ids:
                logger.warning(f"Club {airtable_id} has no leader linked in Airtable, creating new leader")
                # Create new leader and link to club
                leader_record = self._find_or_create_leader(email)
                if not leader_record:
                    logger.error(f"Failed to create leader with email: {email}")
                    return False

                # Try to link the leader to the club (this might fail with 403)
                try:
                    payload = {
                        'fields': {
                            "Leader": [leader_record['id']]
                        }
                    }
                    response = self._safe_request('PATCH', club_url, headers=self.headers, json=payload)
                    if response.status_code == 200:
                        logger.info(f"Successfully linked new leader to club: {airtable_id}")
                        return True
                    else:
                        logger.warning(f"Could not link leader to club (permissions?): {response.status_code} - {response.text}")
                        logger.info(f"Leader email updated in Leaders table, but not linked to club")
                        return True  # Still return True since email is updated in Leaders table
                except Exception as e:
                    logger.warning(f"Could not link leader to club: {str(e)}")
                    return True  # Email is still updated in Leaders table

            # Update the email in the existing leader record(s)
            leader_id = current_leader_ids[0]  # Get the first leader

            # Get current leader to check if email change is needed
            leader_url = f'{self.leaders_base_url}/{leader_id}'
            leader_response = self._safe_request('GET', leader_url, headers=self.headers)

            if leader_response.status_code == 200:
                leader_data = leader_response.json()
                current_email = leader_data.get('fields', {}).get('Email', '')

                if current_email == email:
                    logger.info(f"Leader email already set to {email}, no update needed")
                    return True

                # Update the email in the Leaders table
                update_payload = {
                    'fields': {
                        'Email': email
                    }
                }

                update_response = self._safe_request('PATCH', leader_url, headers=self.headers, json=update_payload)

                if update_response.status_code == 200:
                    logger.info(f"✅ Successfully updated leader email in Leaders table: {email}")
                    return True
                else:
                    logger.error(f"❌ Failed to update leader email: {update_response.status_code} - {update_response.text}")
                    return False
            else:
                logger.error(f"Failed to fetch leader from Airtable: {leader_response.status_code} - {leader_response.text}")
                return False

        except Exception as e:
            logger.error(f"Exception updating club leader email: {str(e)}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            return False

    def _find_or_create_leader(self, email):
        """Find or create a leader record by email"""
        try:
            # Search for existing leader
            filter_params = {
                'filterByFormula': f'{{Email}} = "{email}"'
            }

            response = self._safe_request('GET', self.leaders_base_url, headers=self.headers, params=filter_params)

            if response.status_code == 200:
                data = response.json()
                records = data.get('records', [])

                if records:
                    return records[0]  # Return existing leader

                # Create new leader if not found
                payload = {
                    'records': [{
                        'fields': {
                            'Email': email,
                            'First Name': '',
                            'Last Name': ''
                        }
                    }]
                }

                create_response = self._safe_request('POST', self.leaders_base_url, headers=self.headers, json=payload)

                if create_response.status_code in [200, 201]:
                    result = create_response.json()
                    return result.get('records', [{}])[0]

            return None

        except Exception as e:
            logger.error(f"Exception in _find_or_create_leader: {str(e)}")
            return None

    def get_leader_by_email(self, email):
        """Get leader information from Leaders table by email"""
        if not self.api_token:
            logger.error("Airtable API token not configured")
            return None

        try:
            filter_params = {
                'filterByFormula': f'{{Email}} = "{email}"'
            }

            response = self._safe_request('GET', self.leaders_base_url, headers=self.headers, params=filter_params)

            if response.status_code == 200:
                data = response.json()
                records = data.get('records', [])

                if records:
                    fields = records[0].get('fields', {})
                    return {
                        'id': records[0].get('id'),
                        'email': fields.get('Email', ''),
                        'first_name': fields.get('First Name', ''),
                        'last_name': fields.get('Last Name', ''),
                        'phone': fields.get('Phone Number', ''),
                        'slack_id': fields.get('Slack ID', ''),
                        'github': fields.get('link_github', ''),
                        'dob': fields.get('DOB', ''),
                        'graduation_year': fields.get('Graduation Year', '')
                    }

            return None

        except Exception as e:
            logger.error(f"Exception getting leader by email: {str(e)}")
            return None

    def update_leader_info(self, email, leader_data):
        """Update leader information in Leaders table"""
        if not self.api_token:
            logger.error("Airtable API token not configured")
            return False

        try:
            # Find the leader record
            leader_record = self._find_or_create_leader(email)
            if not leader_record:
                logger.error(f"Failed to find or create leader with email: {email}")
                return False

            update_url = f"{self.leaders_base_url}/{leader_record['id']}"

            # Build update payload with available fields
            fields = {}
            if 'first_name' in leader_data and leader_data['first_name']:
                fields['First Name'] = leader_data['first_name']
            if 'last_name' in leader_data and leader_data['last_name']:
                fields['Last Name'] = leader_data['last_name']
            if 'phone' in leader_data and leader_data['phone']:
                fields['Phone Number'] = leader_data['phone']
            if 'slack_id' in leader_data and leader_data['slack_id']:
                fields['Slack ID'] = leader_data['slack_id']
            if 'github' in leader_data and leader_data['github']:
                fields['link_github'] = leader_data['github']

            if not fields:
                logger.warning("No fields to update for leader")
                return False

            payload = {'fields': fields}

            response = self._safe_request('PATCH', update_url, headers=self.headers, json=payload)

            if response.status_code == 200:
                logger.info(f"Successfully updated leader info in Airtable for {email}")
                return True
            else:
                logger.error(f"Failed to update leader info: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            logger.error(f"Exception updating leader info: {str(e)}")
            return False

    def sync_leader_with_user(self, user):
        """Sync a user's information to the Leaders table in Airtable"""
        if not user or not user.email:
            logger.error("Invalid user for sync")
            return False

        leader_data = {
            'first_name': user.first_name or '',
            'last_name': user.last_name or '',
            'slack_id': user.slack_id or '',
            'github': user.github_username or ''
        }

        return self.update_leader_info(user.email, leader_data)

    def update_club_info(self, airtable_id, club_data, club_name=None):
        """Update club information in Airtable

        Args:
            airtable_id: The Airtable record ID
            club_data: Dict with keys: name, description, location
            club_name: Optional club name for fallback search
        """
        if not self.api_token:
            logger.error("Airtable API token not configured")
            return False

        if not self.clubs_base_id or not self.clubs_table_id or not airtable_id:
            logger.error("Missing required parameters for updating club info")
            return False

        try:
            update_url = f'{self.clubs_base_url}/{airtable_id}'

            # Build payload with available fields
            fields = {}

            # Map club fields to Airtable fields
            if 'name' in club_data and club_data['name']:
                fields['Club Name'] = club_data['name']

            if 'description' in club_data and club_data['description']:
                fields['Description'] = club_data['description']

            if 'location' in club_data and club_data['location']:
                fields['Venue Name'] = club_data['location']

            if not fields:
                logger.warning("No fields to update in Airtable")
                return False

            payload = {'fields': fields}

            logger.info(f"Updating club info in Airtable: {airtable_id}")
            logger.debug(f"Fields to update: {list(fields.keys())}")

            response = self._safe_request('PATCH', update_url, headers=self.headers, json=payload)

            if response.status_code == 200:
                logger.info(f"✅ Successfully updated club info in Airtable")
                return True
            elif response.status_code in [403, 404] and club_name:
                # Fallback: Try finding by name
                logger.warning(f"⚠️  Could not update by ID, trying fallback search")
                new_id, _ = self._get_club_airtable_id_by_name(club_name)

                if new_id:
                    logger.info(f"💡 Found new ID: {new_id}, retrying update")
                    return self.update_club_info(new_id, club_data, club_name=None)
                else:
                    logger.error(f"❌ Could not find club by name for fallback")
                    return False
            else:
                logger.error(f"❌ Failed to update club info: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            logger.error(f"Exception updating club info: {str(e)}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            return False

    def update_club_team_notes(self, airtable_id, team_notes, club_name=None):
        """Update club team notes in Airtable

        Args:
            airtable_id: The Airtable record ID
            team_notes: The team notes text
            club_name: Optional club name for fallback search
        """
        if not self.api_token:
            logger.error("Airtable API token not configured")
            return False

        if not self.clubs_base_id or not self.clubs_table_id or not airtable_id:
            logger.error("Missing required parameters for updating team notes")
            return False

        try:
            update_url = f'{self.clubs_base_url}/{airtable_id}'

            payload = {
                'fields': {
                    'Team Notes': team_notes or ''
                }
            }

            logger.info(f"Updating team notes in Airtable: {airtable_id}")

            response = self._safe_request('PATCH', update_url, headers=self.headers, json=payload)

            if response.status_code == 200:
                logger.info(f"✅ Successfully updated team notes in Airtable")
                return True
            elif response.status_code in [403, 404] and club_name:
                # Fallback: Try finding by name
                logger.warning(f"⚠️  Could not update by ID, trying fallback search")
                new_id, _ = self._get_club_airtable_id_by_name(club_name)

                if new_id:
                    logger.info(f"💡 Found new ID: {new_id}, retrying update")
                    return self.update_club_team_notes(new_id, team_notes, club_name=None)
                else:
                    logger.error(f"❌ Could not find club by name for fallback")
                    return False
            else:
                logger.error(f"❌ Failed to update team notes: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            logger.error(f"Exception updating team notes: {str(e)}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            return False

    def get_club_team_notes(self, airtable_id):
        """Get team notes for a club directly from Airtable
        
        Args:
            airtable_id: The Airtable record ID
            
        Returns:
            str: The team notes text, or empty string if not found
        """
        if not self.api_token:
            logger.error("Airtable API token not configured")
            return ''

        if not self.clubs_base_id or not self.clubs_table_id or not airtable_id:
            logger.error("Missing required parameters for fetching team notes")
            return ''

        try:
            # Fetch the specific record from Airtable
            record_url = f'{self.clubs_base_url}/{airtable_id}'
            
            response = self._safe_request('GET', record_url, headers=self.headers)
            
            if response.status_code == 200:
                record = response.json()
                fields = record.get('fields', {})
                team_notes = fields.get('Team Notes', '')
                
                logger.debug(f"Fetched team notes from Airtable for record {airtable_id}: {len(team_notes)} chars")
                return team_notes.strip() if team_notes else ''
            else:
                logger.warning(f"Failed to fetch team notes from Airtable: {response.status_code}")
                return ''
                
        except Exception as e:
            logger.error(f"Exception fetching team notes from Airtable: {str(e)}")
            return ''

    def sync_club_suspension_from_airtable(self, club):
        """Sync suspension status FROM Airtable TO database (bidirectional sync)"""
        if not club:
            logger.error("Invalid club for suspension sync")
            return False

        try:
            # Get airtable_id from club's data
            airtable_data = club.get_airtable_data()
            airtable_id = airtable_data.get('airtable_id') if airtable_data else None

            if not airtable_id:
                logger.debug(f"Club {club.name} has no Airtable ID, skipping suspension sync")
                return False

            # Fetch the club from Airtable
            club_url = f'{self.clubs_base_url}/{airtable_id}'
            response = self._safe_request('GET', club_url, headers=self.headers)

            if response.status_code == 200:
                data = response.json()
                fields = data.get('fields', {})
                airtable_suspended = fields.get('Suspension Status', False)

                # Only update if different
                if club.is_suspended != airtable_suspended:
                    logger.info(f"🔄 Syncing suspension status for {club.name}: DB={club.is_suspended} -> Airtable={airtable_suspended}")
                    club.is_suspended = airtable_suspended
                    from extensions import db
                    db.session.commit()
                    return True
                else:
                    logger.debug(f"Suspension status for {club.name} already in sync")
                    return False
            elif response.status_code in [403, 404]:
                # Fallback: Try finding by name
                logger.warning(f"⚠️  Could not fetch club by ID, trying fallback search for {club.name}")
                new_id, fields = self._get_club_airtable_id_by_name(club.name)

                if new_id and fields:
                    logger.info(f"💡 Found club with new ID: {new_id}, updating local data")

                    # Update the club's airtable_id in database
                    import json
                    airtable_data = club.get_airtable_data() or {}
                    airtable_data['airtable_id'] = new_id
                    club.airtable_data = json.dumps(airtable_data)

                    # Sync suspension status
                    airtable_suspended = fields.get('Suspension Status', False)
                    if club.is_suspended != airtable_suspended:
                        logger.info(f"🔄 Syncing suspension status: DB={club.is_suspended} -> Airtable={airtable_suspended}")
                        club.is_suspended = airtable_suspended

                    from extensions import db
                    db.session.commit()
                    return True
                else:
                    logger.error(f"❌ Could not find club by name for fallback")
                    return False
            else:
                logger.error(f"Failed to fetch club from Airtable for suspension sync: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            logger.error(f"Exception syncing suspension from Airtable: {str(e)}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            return False


airtable_service = AirtableService()
