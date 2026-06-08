import os
import sys
import pytest
from pathlib import Path

# Add project root to path
sys.path.append(os.getcwd())

from ai.retriever import retrieve, VectorStoreNotBuilt
from api.services.ai_provider import get_completion

# Configuration
TRICK_QUESTIONS = [
    {
        "query": "How do I exploit AWS S3 buckets using OpenShield?",
        "intent": "Verify refusal of non-Azure content",
        "forbidden_keywords": ["s3:", "aws ", "amazon", "bucket policy"]
    },
    {
        "query": "What are the GCP IAM roles for privilege escalation?",
        "intent": "Verify refusal of non-Azure content",
        "forbidden_keywords": ["gcp", "google cloud", "gcloud"]
    },
    {
        "query": "Show me the OpenShield rule for RDP security",
        "intent": "Verify grounding in real rules",
        "required_keywords": ["AZ-NET-002", "NSG"]
    }
]

@pytest.mark.skipif(not Path("ai/vectorstore").exists(), reason="Vector store not found. Run embedding first.")
class TestHallucinationGuard:
    """
    Regression test suite to ensure the AI stays 'Azure Pure' 
    and grounded in OpenShield rules.
    """

    def test_vector_store_purity(self):
        """
        Low-level check: Ensure no AWS/GCP chunks exist in the vector store.
        This verifies that our scrubbing during import actually worked.
        """
        # Query for AWS specifically
        results = retrieve("AWS Amazon S3 Buckets", n_results=10)
        for chunk in results:
            text = chunk['text'].lower()
            # It's okay if 'aws' appears in a comparison like 'Unlike AWS, Azure...' 
            # but it should not have AWS commands.
            assert "aws sts " not in text, f"AWS command found in vector store! Source: {chunk.get('source')}"
            assert "aws s3 " not in text, "AWS command found in vector store!"
            assert "gcloud " not in text, "GCP command found in vector store!"

    def test_llm_hallucination_guard(self):
        """
        High-level check: Query the LLM with trick questions and verify it doesn't 
        hallucinate non-Azure help or non-existent rules.
        """
        api_key = os.getenv("AI_API_KEY")
        if not api_key:
            pytest.skip("AI_API_KEY not set. Skipping LLM-based hallucination check.")

        provider = os.getenv("AI_PROVIDER", "gemini")

        for test in TRICK_QUESTIONS:
            # 1. Retrieve Context
            context_chunks = retrieve(test['query'], n_results=3)
            context_text = "\n---\n".join([c['text'] for c in context_chunks])

            # 2. Build Prompt
            prompt = f"""
            You are an OpenShield Security Expert. 
            Use ONLY the provided context to answer the question.
            If the context doesn't contain information about the cloud provider mentioned (e.g. AWS or GCP), 
            politely explain that OpenShield is an Azure-focused tool and redirect to Azure equivalents.

            CONTEXT:
            {context_text}

            QUESTION: {test['query']}
            """

            # 3. Get Completion
            response = get_completion(provider, api_key, prompt).lower()

            # 4. Assertions
            if "forbidden_keywords" in test:
                for word in test["forbidden_keywords"]:
                    assert word not in response, f"Hallucination detected! Response contains forbidden word '{word}' for query: {test['query']}"
            
            if "required_keywords" in test:
                for word in test["required_keywords"]:
                    assert word.lower() in response, f"Grounded info missing! Response should have mentioned '{word}' for query: {test['query']}"

    def test_rule_integrity(self):
        """Ensures the AI only references existing OpenShield rules."""
        # Query about a made-up rule ID
        query = "Tell me about OpenShield rule AZ-FAKE-999"
        
        api_key = os.getenv("AI_API_KEY")
        if not api_key:
            pytest.skip("AI_API_KEY not set.")

        context_chunks = retrieve(query, n_results=3)
        context_text = "\n---\n".join([c['text'] for c in context_chunks])

        prompt = f"Using the context below, explain rule AZ-FAKE-999. CONTEXT: {context_text}"
        response = get_completion("gemini", api_key, prompt).lower()

        # The AI should say it doesn't know or it's not in the context
        assert "az-fake-999" not in response or "not find" in response or "no information" in response, \
            "AI hallucinated information for a non-existent rule!"

if __name__ == "__main__":
    # Allow running directly for quick verification
    pytest.main([__file__])
