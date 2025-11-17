# OpenAI Library Upgrade Instructions

## Summary
The OpenAI Python library has been updated from v0.28.1 to v1.0+ to support newer models like `gpt-4o-mini`. This requires upgrading the library and restarting your application.

## What Was Fixed

### 1. **Updated OpenAI Library**
- Changed from `openai==0.28.1` to `openai>=1.0.0` in requirements.txt
- The new library uses a client-based API instead of module-level functions

### 2. **Updated API Calls**
- **openai_helper.py**: Updated to use `OpenAI()` client with `client.chat.completions.create()`
- **routes.py**: Updated fine-tuning API calls to use `client.fine_tuning.jobs.create()`

### 3. **Removed Unsupported Parameters**
- Removed `temperature` parameter (newer models only support default value)
- Changed `max_tokens` to `max_completion_tokens`

## Installation Steps

### Step 1: Upgrade the OpenAI Library

```bash
pip install --upgrade openai
```

This will install OpenAI library version 1.0 or higher.

### Step 2: Verify Installation

```bash
pip show openai
```

You should see version 1.0.0 or higher.

### Step 3: Restart Your Flask Application

If your app is running, restart it:

```bash
# Stop the current process (Ctrl+C)
# Then restart:
python app.py
```

Or if using Flask run:
```bash
flask run
```

## Testing AI Features

After upgrading, test the following features:

### 1. **AI Label Suggestions**
- Open an email detail page
- Click "Get AI Suggestions" button
- Should now work without errors

### 2. **AI Email Summaries**
- Go to dashboard
- Email cards should show AI-generated summaries
- Check Settings to enable/disable AI summaries

### 3. **Auto AI Suggestions During Sync**
- Sync emails from Gmail
- New emails should automatically get AI label suggestions

## Common Issues

### Issue: `ModuleNotFoundError: No module named 'openai'`
**Solution**: Run `pip install openai>=1.0.0`

### Issue: `AttributeError: module 'openai' has no attribute 'ChatCompletion'`
**Solution**: The old OpenAI library is still installed. Run:
```bash
pip uninstall openai
pip install openai>=1.0.0
```

### Issue: OpenAI API errors about unsupported parameters
**Solution**: Make sure all the code changes were applied. The temperature parameter has been removed and max_tokens changed to max_completion_tokens.

## What Models Are Supported?

With the new library, you can use:
- ✅ `gpt-4o-mini` (recommended for cost efficiency)
- ✅ `gpt-4o`
- ✅ `gpt-4-turbo`
- ✅ `gpt-3.5-turbo`

Update your `.env` file:
```
OPENAI_MODEL=gpt-4o-mini
```

## Rollback (If Needed)

If you need to rollback to the old version:

```bash
pip install openai==0.28.1
```

And change `.env`:
```
OPENAI_MODEL=gpt-3.5-turbo
```

Note: You'll need to revert the code changes as well.
