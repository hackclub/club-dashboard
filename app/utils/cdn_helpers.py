"""
CDN Helper Functions
Handles image uploads to Hack Club CDN
"""

import os
import uuid
import base64
import requests
from flask import current_app, request


def upload_to_hackclub_cdn(image_data_list):
    """
    Upload images to Hack Club CDN

    Args:
        image_data_list: List of tuples (image_data_bytes, file_extension)

    Returns:
        tuple: (success: bool, result: list of CDN URLs or error message)
    """
    try:
        cdn_token = os.getenv('HACKCLUB_CDN_TOKEN')
        if not cdn_token:
            current_app.logger.error("HACKCLUB_CDN_TOKEN not configured")
            return False, "Image upload service not configured"

        if not image_data_list:
            return False, "No images provided"

        temp_upload_dir = os.path.join(current_app.root_path, '..', 'static', 'temp')
        os.makedirs(temp_upload_dir, exist_ok=True)

        temp_files = []
        temp_urls = []

        try:
            for image_data, file_ext in image_data_list:
                temp_filename = f"upload_{uuid.uuid4()}{file_ext}"
                temp_file_path = os.path.join(temp_upload_dir, temp_filename)

                with open(temp_file_path, 'wb') as f:
                    f.write(image_data)

                temp_files.append(temp_file_path)

                temp_url = f"{request.url_root}static/temp/{temp_filename}"
                temp_urls.append(temp_url)

            current_app.logger.info(f'Uploading {len(temp_urls)} images to Hack Club CDN')

            cdn_response = requests.post(
                'https://cdn.hackclub.com/api/v3/new',
                headers={
                    'Authorization': f'Bearer {cdn_token}',
                    'Content-Type': 'application/json'
                },
                json=temp_urls,  # Send array of URLs
                timeout=60
            )

            if cdn_response.status_code != 200:
                current_app.logger.error(f"CDN upload failed: {cdn_response.status_code} - {cdn_response.text}")
                return False, "Failed to upload images to CDN"

            cdn_data = cdn_response.json()

            if 'files' in cdn_data and len(cdn_data['files']) > 0:
                cdn_urls = [file_info['deployedUrl'] for file_info in cdn_data['files']]
                current_app.logger.info(f'Successfully uploaded {len(cdn_urls)} images to CDN')
                return True, cdn_urls
            else:
                current_app.logger.error(f"Unexpected CDN response format: {cdn_data}")
                return False, "Failed to process upload response"

        finally:
            for temp_file in temp_files:
                try:
                    if os.path.exists(temp_file):
                        os.unlink(temp_file)
                except Exception as e:
                    current_app.logger.error(f"Error cleaning up temp file {temp_file}: {str(e)}")

    except requests.RequestException as e:
        current_app.logger.error(f"Error uploading to CDN: {str(e)}")
        return False, "Failed to connect to image service"
    except Exception as e:
        current_app.logger.error(f"Error in upload_to_hackclub_cdn: {str(e)}")
        return False, "Failed to upload images"


def parse_base64_images(base64_images_list, max_size=10 * 1024 * 1024):
    """
    Parse and validate base64 image data

    Args:
        base64_images_list: List of base64 encoded images (data URLs)
        max_size: Maximum file size in bytes (default 10MB)

    Returns:
        list: List of tuples (image_data_bytes, file_extension)
    """
    allowed_mime_types = {'image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp'}
    ext_map = {
        'image/jpeg': '.jpg',
        'image/jpg': '.jpg',
        'image/png': '.png',
        'image/gif': '.gif',
        'image/webp': '.webp'
    }

    parsed_images = []

    for idx, base64_image in enumerate(base64_images_list):
        try:
            if not base64_image.startswith('data:image/'):
                current_app.logger.warning(f'Invalid image format for image {idx}')
                continue

            header, data_part = base64_image.split(',', 1)
            mime_type = header.split(':')[1].split(';')[0]

            if mime_type not in allowed_mime_types:
                current_app.logger.warning(f'Invalid MIME type: {mime_type}')
                continue

            image_data = base64.b64decode(data_part)
            if len(image_data) > max_size:
                current_app.logger.warning(f'Image {idx} too large: {len(image_data)} bytes')
                continue

            file_ext = ext_map.get(mime_type, '.jpg')

            parsed_images.append((image_data, file_ext))

        except Exception as e:
            current_app.logger.error(f'Error parsing image {idx}: {str(e)}')
            continue

    return parsed_images
