from openai import OpenAI

from app.settings import settings

gpt_client = OpenAI(
    api_key=settings.openai_api_key,
    organization=settings.openai_org_id,
)


def ask_gpt(
    prompt: str,
    model: str = "gpt-3.5-turbo",
):
    """
    Ask GPT-4 for a response.
    """
    response = gpt_client.chat.completions.create(
        model=model,
        messages=[
            {
                "role": "user",
                "content": prompt,
            },
        ],
    )
    return response.choices[0].message.content
