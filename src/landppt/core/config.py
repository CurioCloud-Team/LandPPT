"""
Configuration management for LandPPT AI features
"""

import os
from typing import Optional, Dict, Any
from pydantic import Field
from pydantic_settings import BaseSettings
from dotenv import load_dotenv

# Load environment variables with error handling
try:
    load_dotenv()
except (PermissionError, FileNotFoundError) as e:
    # Silently continue if .env file is not accessible
    # This allows the application to work with system environment variables
    pass
except Exception as e:
    # Log other errors but continue
    import logging
    logging.getLogger(__name__).warning(f"Could not load .env file: {e}")

class AIConfig(BaseSettings):
    """AI configuration settings"""
    
    # OpenAI Configuration
    openai_api_key: Optional[str] = Field(default=None, env="OPENAI_API_KEY")
    openai_base_url: str = Field(default="https://api.openai.com/v1", env="OPENAI_BASE_URL")
    openai_model: str = Field(default="gpt-3.5-turbo", env="OPENAI_MODEL")
    
    # Anthropic Configuration
    anthropic_api_key: Optional[str] = Field(default=None, env="ANTHROPIC_API_KEY")
    anthropic_model: str = Field(default="claude-3-haiku-20240307", env="ANTHROPIC_MODEL")

    # Google Gemini Configuration
    google_api_key: Optional[str] = Field(default=None, env="GOOGLE_API_KEY")
    google_base_url: str = Field(default="https://generativelanguage.googleapis.com", env="GOOGLE_BASE_URL")
    google_model: str = Field(default="gemini-1.5-flash", env="GOOGLE_MODEL")
    
    # Azure OpenAI Configuration
    azure_openai_api_key: Optional[str] = Field(default=None, env="AZURE_OPENAI_API_KEY")
    azure_openai_endpoint: Optional[str] = Field(default=None, env="AZURE_OPENAI_ENDPOINT")
    azure_openai_api_version: str = Field(default="2024-02-15-preview", env="AZURE_OPENAI_API_VERSION")
    azure_openai_deployment_name: Optional[str] = Field(default=None, env="AZURE_OPENAI_DEPLOYMENT_NAME")
    
    # Ollama Configuration
    ollama_base_url: str = Field(default="http://localhost:11434", env="OLLAMA_BASE_URL")
    ollama_model: str = Field(default="llama2", env="OLLAMA_MODEL")
    
    # 302.AI Configuration
    ai_302ai_api_key: Optional[str] = Field(default=None, env="302AI_API_KEY", alias="302ai_api_key")
    ai_302ai_base_url: str = Field(default="https://api.302.ai/v1", env="302AI_BASE_URL", alias="302ai_base_url")
    ai_302ai_model: str = Field(default="gpt-4o", env="302AI_MODEL", alias="302ai_model")
    
    # Hugging Face Configuration
    huggingface_api_token: Optional[str] = Field(default=None, env="HUGGINGFACE_API_TOKEN")

    # Tavily API Configuration (for research functionality)
    tavily_api_key: Optional[str] = Field(default=None, env="TAVILY_API_KEY")
    tavily_max_results: int = Field(default=10, env="TAVILY_MAX_RESULTS")
    tavily_search_depth: str = Field(default="advanced", env="TAVILY_SEARCH_DEPTH")
    tavily_include_domains: Optional[str] = Field(default=None, env="TAVILY_INCLUDE_DOMAINS")
    tavily_exclude_domains: Optional[str] = Field(default=None, env="TAVILY_EXCLUDE_DOMAINS")

    # SearXNG Configuration (for research functionality)
    searxng_host: Optional[str] = Field(default=None, env="SEARXNG_HOST")
    searxng_max_results: int = Field(default=10, env="SEARXNG_MAX_RESULTS")
    searxng_language: str = Field(default="auto", env="SEARXNG_LANGUAGE")
    searxng_timeout: int = Field(default=30, env="SEARXNG_TIMEOUT")

    # Research Configuration
    research_provider: str = Field(default="tavily", env="RESEARCH_PROVIDER")  # tavily, searxng, both
    research_enable_content_extraction: bool = Field(default=True, env="RESEARCH_ENABLE_CONTENT_EXTRACTION")
    research_max_content_length: int = Field(default=5000, env="RESEARCH_MAX_CONTENT_LENGTH")
    research_extraction_timeout: int = Field(default=30, env="RESEARCH_EXTRACTION_TIMEOUT")

    # Apryse SDK Configuration (for PPTX export functionality)
    apryse_license_key: Optional[str] = Field(default=None, env="APRYSE_LICENSE_KEY")

    # Provider Selection
    default_ai_provider: str = Field(default="openai", env="DEFAULT_AI_PROVIDER")
    
    # Generation Parameters
    max_tokens: int = Field(default=16384, env="MAX_TOKENS")
    temperature: float = Field(default=0.7, env="TEMPERATURE")
    top_p: float = Field(default=1.0, env="TOP_P")
    
    # Feature Flags
    enable_network_mode: bool = Field(default=True, env="ENABLE_NETWORK_MODE")
    enable_local_models: bool = Field(default=False, env="ENABLE_LOCAL_MODELS")
    enable_streaming: bool = Field(default=True, env="ENABLE_STREAMING")
    
    # Logging
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    log_ai_requests: bool = Field(default=False, env="LOG_AI_REQUESTS")
    
    model_config = {
        "env_file": ".env",
        "case_sensitive": False,
        "extra": "ignore"
    }



    def get_provider_config(self, provider: Optional[str] = None) -> Dict[str, Any]:
        """Get configuration for a specific AI provider"""
        provider = provider or self.default_ai_provider

        # Built-in providers
        configs = {
            "openai": {
                "api_key": self.openai_api_key,
                "base_url": self.openai_base_url,
                "model": self.openai_model,
                "max_tokens": self.max_tokens,
                "temperature": self.temperature,
                "top_p": self.top_p,
            },
            "anthropic": {
                "api_key": self.anthropic_api_key,
                "model": self.anthropic_model,
                "max_tokens": self.max_tokens,
                "temperature": self.temperature,
                "top_p": self.top_p,
            },
            "google": {
                "api_key": self.google_api_key,
                "base_url": self.google_base_url,
                "model": self.google_model,
                "max_tokens": self.max_tokens,
                "temperature": self.temperature,
                "top_p": self.top_p,
            },
            "gemini": {  # Alias for google
                "api_key": self.google_api_key,
                "base_url": self.google_base_url,
                "model": self.google_model,
                "max_tokens": self.max_tokens,
                "temperature": self.temperature,
                "top_p": self.top_p,
            },
            "azure_openai": {
                "api_key": self.azure_openai_api_key,
                "endpoint": self.azure_openai_endpoint,
                "api_version": self.azure_openai_api_version,
                "deployment_name": self.azure_openai_deployment_name,
                "max_tokens": self.max_tokens,
                "temperature": self.temperature,
                "top_p": self.top_p,
            },
            "ollama": {
                "base_url": self.ollama_base_url,
                "model": self.ollama_model,
                "max_tokens": self.max_tokens,
                "temperature": self.temperature,
                "top_p": self.top_p,
            },
            "302ai": {
                "api_key": self.ai_302ai_api_key,
                "base_url": self.ai_302ai_base_url,
                "model": self.ai_302ai_model,
                "max_tokens": self.max_tokens,
                "temperature": self.temperature,
                "top_p": self.top_p,
            }
        }

        return configs.get(provider, configs.get("openai", {}))
    
    def is_provider_available(self, provider: str) -> bool:
        """Check if a provider is properly configured"""
        config = self.get_provider_config(provider)

        # Built-in providers
        if provider == "openai":
            return bool(config.get("api_key"))
        elif provider == "anthropic":
            return bool(config.get("api_key"))
        elif provider == "google" or provider == "gemini":
            return bool(config.get("api_key"))
        elif provider == "azure_openai":
            return bool(config.get("api_key") and config.get("endpoint"))
        elif provider == "ollama":
            return self.enable_local_models
        elif provider == "302ai":
            return bool(config.get("api_key"))

        return False
    
    def get_available_providers(self) -> list[str]:
        """Get list of available AI providers"""
        providers = []

        # Add built-in providers
        for provider in ["openai", "anthropic", "google", "gemini", "azure_openai", "ollama", "302ai"]:
            if self.is_provider_available(provider):
                providers.append(provider)

        return providers

# Global configuration instance
ai_config = AIConfig()

def reload_ai_config():
    """Reload AI configuration from environment variables"""
    global ai_config
    # Force reload environment variables with error handling
    from dotenv import load_dotenv
    import os
    env_file = os.path.join(os.getcwd(), '.env')
    try:
        load_dotenv(env_file, override=True)
    except (PermissionError, FileNotFoundError) as e:
        # Silently continue if .env file is not accessible
        pass
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning(f"Could not reload .env file: {e}")

    # Force update the existing instance with new values from environment
    ai_config.openai_model = os.environ.get('OPENAI_MODEL', ai_config.openai_model)
    ai_config.openai_base_url = os.environ.get('OPENAI_BASE_URL', ai_config.openai_base_url)
    ai_config.openai_api_key = os.environ.get('OPENAI_API_KEY', ai_config.openai_api_key)
    ai_config.anthropic_api_key = os.environ.get('ANTHROPIC_API_KEY', ai_config.anthropic_api_key)
    ai_config.anthropic_model = os.environ.get('ANTHROPIC_MODEL', ai_config.anthropic_model)
    ai_config.google_api_key = os.environ.get('GOOGLE_API_KEY', ai_config.google_api_key)
    ai_config.google_base_url = os.environ.get('GOOGLE_BASE_URL', ai_config.google_base_url)
    ai_config.google_model = os.environ.get('GOOGLE_MODEL', ai_config.google_model)
    ai_config.ai_302ai_api_key = os.environ.get('302AI_API_KEY', ai_config.ai_302ai_api_key)
    ai_config.ai_302ai_base_url = os.environ.get('302AI_BASE_URL', ai_config.ai_302ai_base_url)
    ai_config.ai_302ai_model = os.environ.get('302AI_MODEL', ai_config.ai_302ai_model)
    ai_config.default_ai_provider = os.environ.get('DEFAULT_AI_PROVIDER', ai_config.default_ai_provider)
    ai_config.max_tokens = int(os.environ.get('MAX_TOKENS', str(ai_config.max_tokens)))
    ai_config.temperature = float(os.environ.get('TEMPERATURE', str(ai_config.temperature)))
    ai_config.top_p = float(os.environ.get('TOP_P', str(ai_config.top_p)))

    # Update Tavily configuration
    ai_config.tavily_api_key = os.environ.get('TAVILY_API_KEY', ai_config.tavily_api_key)
    ai_config.tavily_max_results = int(os.environ.get('TAVILY_MAX_RESULTS', str(ai_config.tavily_max_results)))
    ai_config.tavily_search_depth = os.environ.get('TAVILY_SEARCH_DEPTH', ai_config.tavily_search_depth)
    ai_config.tavily_include_domains = os.environ.get('TAVILY_INCLUDE_DOMAINS', ai_config.tavily_include_domains)
    ai_config.tavily_exclude_domains = os.environ.get('TAVILY_EXCLUDE_DOMAINS', ai_config.tavily_exclude_domains)

    # Update SearXNG configuration
    ai_config.searxng_host = os.environ.get('SEARXNG_HOST', ai_config.searxng_host)
    ai_config.searxng_max_results = int(os.environ.get('SEARXNG_MAX_RESULTS', str(ai_config.searxng_max_results)))
    ai_config.searxng_language = os.environ.get('SEARXNG_LANGUAGE', ai_config.searxng_language)
    ai_config.searxng_timeout = int(os.environ.get('SEARXNG_TIMEOUT', str(ai_config.searxng_timeout)))

    # Update Research configuration
    ai_config.research_provider = os.environ.get('RESEARCH_PROVIDER', ai_config.research_provider)
    ai_config.research_enable_content_extraction = os.environ.get('RESEARCH_ENABLE_CONTENT_EXTRACTION', str(ai_config.research_enable_content_extraction)).lower() == 'true'
    ai_config.research_max_content_length = int(os.environ.get('RESEARCH_MAX_CONTENT_LENGTH', str(ai_config.research_max_content_length)))
    ai_config.research_extraction_timeout = int(os.environ.get('RESEARCH_EXTRACTION_TIMEOUT', str(ai_config.research_extraction_timeout)))

    ai_config.apryse_license_key = os.environ.get('APRYSE_LICENSE_KEY', ai_config.apryse_license_key)

class AppConfig(BaseSettings):
    """Application configuration"""
    
    # Server Configuration
    host: str = Field(default="0.0.0.0", env="HOST")
    port: int = Field(default=8000, env="PORT")
    debug: bool = Field(default=True, env="DEBUG")
    reload: bool = Field(default=True, env="RELOAD")
    
    # Database Configuration (for future use)
    database_url: str = Field(default="mysql+pymysql://user:pass@localhost:3306/curio_cloud", env="DATABASE_URL")
    
    # Security Configuration
    secret_key: str = Field(default="your-secret-key-here", env="SECRET_KEY")
    access_token_expire_minutes: int = Field(default=30, env="ACCESS_TOKEN_EXPIRE_MINUTES")
    
    # File Upload Configuration
    max_file_size: int = Field(default=10 * 1024 * 1024, env="MAX_FILE_SIZE")  # 10MB
    upload_dir: str = Field(default="uploads", env="UPLOAD_DIR")
    
    # Cache Configuration
    cache_ttl: int = Field(default=3600, env="CACHE_TTL")  # 1 hour
    
    model_config = {
        "case_sensitive": False,
        "extra": "ignore"
    }

# Global app configuration instance
app_config = AppConfig()
