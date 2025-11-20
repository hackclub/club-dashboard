"""
Hackatime Service for fetching user statistics and projects
"""
import os
import requests

# This will be properly initialized when imported by the app
app = None


def init_service(flask_app):
    """Initialize the service with app context"""
    global app
    app = flask_app


class HackatimeService:
    def __init__(self):
        self.base_url = "https://hackatime.hackclub.com/api/v1"
        self.bypass_token = os.environ.get('HACKATIME_RL_BYPASS')

    def get_user_stats(self, api_key):
        if not api_key:
            app.logger.warning("get_user_stats: No API key provided")
            return None

        masked_key = f"{api_key[:8]}...{api_key[-4:]}" if len(api_key) > 12 else "***"
        app.logger.info(f"get_user_stats: Making request to Hackatime API with key {masked_key}")

        url = f"{self.base_url}/users/my/stats?features=projects"
        headers = {"Authorization": f"Bearer {api_key}"}

        if self.bypass_token:
            headers["Rack-Attack-Bypass"] = self.bypass_token

        try:
            app.logger.info(f"get_user_stats: Requesting URL: {url}")
            response = requests.get(url, headers=headers, timeout=10)
            app.logger.info(f"get_user_stats: Response status: {response.status_code}")

            if response.status_code == 200:
                data = response.json()
                app.logger.info(f"get_user_stats: Success - received data with keys: {list(data.keys()) if isinstance(data, dict) else 'non-dict response'}")
                if isinstance(data, dict) and 'data' in data:
                    projects_count = len(data['data'].get('projects', []))
                    app.logger.info(f"get_user_stats: Found {projects_count} projects in response")
                else:
                    app.logger.warning("get_user_stats: Response missing 'data' key or not a dict")
                return data
            else:
                app.logger.error(f"get_user_stats: API request failed with status {response.status_code}")
                try:
                    error_body = response.text[:500]  # Limit error body length
                    app.logger.error(f"get_user_stats: Error response body: {error_body}")
                except:
                    app.logger.error("get_user_stats: Could not read error response body")
                return None
        except requests.exceptions.Timeout:
            app.logger.error("get_user_stats: Request timed out after 10 seconds")
            return None
        except requests.exceptions.RequestException as e:
            app.logger.error(f"get_user_stats: Request exception: {str(e)}")
            return None
        except Exception as e:
            app.logger.error(f"get_user_stats: Unexpected error: {str(e)}")
            return None

    def get_user_projects(self, api_key):
        masked_key = f"{api_key[:8]}...{api_key[-4:]}" if len(api_key) > 12 else "***"
        app.logger.info(f"get_user_projects: Starting for API key {masked_key}")

        stats = self.get_user_stats(api_key)
        if not stats:
            app.logger.warning("get_user_projects: get_user_stats returned None")
            return []

        if 'data' not in stats:
            app.logger.warning(f"get_user_projects: stats missing 'data' key. Stats keys: {list(stats.keys())}")
            return []

        projects = stats['data'].get('projects', [])
        app.logger.info(f"get_user_projects: Found {len(projects)} total projects")

        if not projects:
            app.logger.info("get_user_projects: No projects found in API response")
            return []

        for i, project in enumerate(projects[:5]):  # Log first 5 projects
            project_name = project.get('name', 'unnamed')
            total_seconds = project.get('total_seconds', 0)
            app.logger.info(f"get_user_projects: Project {i+1}: '{project_name}' with {total_seconds} seconds")

        active_projects = [p for p in projects if p.get('total_seconds', 0) > 0]
        app.logger.info(f"get_user_projects: {len(active_projects)} projects have activity (>0 seconds)")

        active_projects.sort(key=lambda x: x.get('total_seconds', 0), reverse=True)

        for project in active_projects:
            total_seconds = project.get('total_seconds', 0)
            project['formatted_time'] = self.format_duration(total_seconds)

        app.logger.info(f"get_user_projects: Returning {len(active_projects)} active projects")
        return active_projects

    def format_duration(self, total_seconds):
        if total_seconds < 60:
            return f"{total_seconds}s"
        minutes = total_seconds // 60
        hours = minutes // 60
        days = hours // 24
        remaining_hours = hours % 24
        remaining_minutes = minutes % 60
        parts = []
        if days > 0:
            parts.append(f"{days}d")
        if remaining_hours > 0:
            parts.append(f"{remaining_hours}h")
        if remaining_minutes > 0:
            parts.append(f"{remaining_minutes}m")
        return " ".join(parts) if parts else "0m"
