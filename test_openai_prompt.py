"""
Test script to show exactly what prompt is being sent to OpenAI
and what response we get back.
"""

import os
from dotenv import load_dotenv
from openai import OpenAI
import json

load_dotenv()

# Get OpenAI client
client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
model = os.getenv('OPENAI_MODEL', 'gpt-4o-mini')

# Sample labels (similar to what the app would have)
label_contexts = [
    {'name': '1. Personal', 'description': 'Friends, family, or personal matters.', 'keywords': 'family, friend, personal'},
    {'name': '10. Work', 'description': 'Tasks, projects, or communication related to your job.', 'keywords': 'work, project, meeting, deadline'},
    {'name': '2. House', 'description': 'No description provided.', 'keywords': 'N/A'},
]

# Build the prompt exactly as the app does
label_descriptions = "\n".join(
    f"- {ctx['name']}: {ctx['description'] or 'No description provided.'} "
    f"Keywords: {ctx['keywords'] or 'N/A'}"
    for ctx in label_contexts
)

subject = "Team meeting tomorrow"
body = "Hi everyone, just a reminder about our team meeting tomorrow at 3pm. Please review the project updates before the meeting."

prompt = (
    "You are an assistant that classifies emails for a user. "
    "Only choose labels from the provided list and return their exact names as JSON.\n\n"
    f"Available labels:\n{label_descriptions}\n\n"
    "Instructions:\n"
    "- Return a JSON array with up to three label names.\n"
    "- Choose labels only if the email clearly matches the label meaning.\n"
    "- Do not invent new labels or alter the provided names.\n\n"
    f"Subject: {subject}\n"
    f"Body:\n{body[:6000]}\n\n"
    'Respond with JSON only, e.g. ["LabelA", "LabelB"].'
)

print("=" * 80)
print("MODEL BEING USED:")
print("=" * 80)
print(f"{model}\n")

print("=" * 80)
print("FULL PROMPT BEING SENT:")
print("=" * 80)
print(prompt)
print("\n")

print("=" * 80)
print("CALLING OPENAI API...")
print("=" * 80)

try:
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": "You classify emails into user-defined folders."},
            {"role": "user", "content": prompt},
        ],
        max_completion_tokens=120,
    )

    content = response.choices[0].message.content

    print("\n")
    print("=" * 80)
    print("RAW RESPONSE FROM OPENAI:")
    print("=" * 80)
    print(f'"{content}"')
    print(f"\nType: {type(content).__name__}")
    print(f"Length: {len(content) if content else 0}")

    # Try to parse
    print("\n")
    print("=" * 80)
    print("ATTEMPTING TO PARSE:")
    print("=" * 80)

    if content:
        content_clean = content.strip()

        # Strip markdown fences if present
        if content_clean.startswith('```'):
            print("Found markdown code fence, stripping...")
            content_clean = content_clean.split('\n', 1)[1] if '\n' in content_clean else content_clean[3:]
            if content_clean.endswith('```'):
                content_clean = content_clean.rsplit('\n', 1)[0] if '\n' in content_clean[:-3] else content_clean[:-3]
            content_clean = content_clean.strip()
            print(f'After stripping fences: "{content_clean}"')

        try:
            suggestions = json.loads(content_clean)
            print(f"\nSuccessfully parsed JSON!")
            print(f"Result: {suggestions}")
            print(f"Type: {type(suggestions).__name__}")

            if isinstance(suggestions, list):
                result = [str(label).strip() for label in suggestions if str(label).strip()]
                print(f"\nFinal suggestions: {result}")
            else:
                print(f"\nERROR: Result is not a list, it's a {type(suggestions).__name__}")
        except json.JSONDecodeError as e:
            print(f"\nERROR: Failed to parse as JSON: {e}")
            print(f"Content that failed to parse: '{content_clean}'")
    else:
        print("ERROR: No content received from OpenAI")

except Exception as e:
    print(f"\nERROR: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "=" * 80)
