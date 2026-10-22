"""Demo app: uses LiteLLM as a library (imports alone are not flagged;
only version evidence is)."""
import litellm

response = litellm.completion(model="gpt-4o", messages=[])
