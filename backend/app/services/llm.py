import json
from typing import Any

from openai import OpenAI, OpenAIError

from app.core.config import get_settings


class LLMError(Exception):
    pass


class LLMClient:
    def __init__(self):
        settings = get_settings()
        if not settings.llm_api_key:
            raise LLMError("LLM_API_KEY is not configured.")
        
        self.model = settings.llm_model
        
        client_kwargs = {"api_key": settings.llm_api_key}
        if settings.llm_api_base:
            client_kwargs["base_url"] = settings.llm_api_base
            
        self.client = OpenAI(**client_kwargs)

    def generate_json(self, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        """
        Generates a structured JSON response from the LLM.
        The prompts should explicitly instruct the LLM to output valid JSON.
        """
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                response_format={"type": "json_object"},
                temperature=0.0,  # Maximize determinism
            )
            
            content = response.choices[0].message.content
            if not content:
                raise LLMError("LLM returned an empty response.")
                
            return json.loads(content)
        except OpenAIError as e:
            raise LLMError(f"LLM Provider Error: {e}")
        except json.JSONDecodeError as e:
            raise LLMError(f"LLM returned invalid JSON: {e}")
        except Exception as e:
            raise LLMError(f"Unexpected LLM Error: {e}")


def validate_evidence_citations(text: str, valid_citation_ids: set[str]) -> tuple[str, bool]:
    import re
    citation_regex = re.compile(r"\[(obs_\w+|inf_\w+|ev_\w+|\w+)\]")
    found_citations = citation_regex.findall(text)
    if not found_citations:
        return text, True

    all_valid = True
    for citation_id in found_citations:
        if citation_id not in valid_citation_ids:
            all_valid = False
            text = text.replace(f"[{citation_id}]", "[UNGROUNDED_CLAIM_REJECTED]")

    return text, all_valid

