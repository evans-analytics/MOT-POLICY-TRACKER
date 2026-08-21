import io
import json
import os

import pdfplumber
from google import genai


REQUIRED_FIELDS = (
    "full_name",
    "phone",
    "email",
    "policy_number",
    "policy_type",
    "start_date",
    "end_date",
    "status",
    "shelf_location",
)


def extract_policy_from_pdf(pdf_bytes):
    """Extract policy fields from a text-based PDF with Gemini."""
    text = ""
    try:
        with pdfplumber.open(io.BytesIO(pdf_bytes)) as pdf:
            for page in pdf.pages:
                text += (page.extract_text() or "") + "\n"
    except Exception as error:
        return None, f"Error reading PDF: {error}"

    if not text.strip():
        return None, "Could not extract text from PDF"

    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key or api_key == "YOUR_API_KEY_HERE":
        return None, "Gemini API key not configured. Set GEMINI_API_KEY in .env."

    prompt = f"""You are a data extraction assistant. Extract policy information from the following document text and return ONLY a JSON object with these exact keys:
- full_name (client full name)
- phone (phone number, empty string if not found)
- email (email address, empty string if not found)
- policy_number (policy number or ID)
- policy_type (type of policy e.g. Motor, Life, Fire, Health)
- start_date (in YYYY-MM-DD format, empty string if not found)
- end_date (in YYYY-MM-DD format, empty string if not found)
- status (Active or Expired)
- shelf_location (empty string if not found)

Return ONLY the JSON object, no explanation, no markdown, no backticks.

Document text:
{text[:3000]}"""

    try:
        response = genai.Client(api_key=api_key).models.generate_content(
            model=os.getenv("GEMINI_MODEL", "gemini-1.5-flash"),
            contents=prompt,
        )
        raw = (response.text or "").strip()
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None, "AI could not parse the document. Please fill in manually."
    except Exception as error:
        return None, f"API Error: {error}. Check your API key is valid."

    if not isinstance(data, dict):
        return None, "AI returned an invalid data structure. Please fill in manually."
    normalized = {field: str(data.get(field, "") or "") for field in REQUIRED_FIELDS}
    if normalized["status"] not in {"", "Active", "Expired"}:
        normalized["status"] = ""
    return normalized, None
