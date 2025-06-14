def api_response(success: bool, message: str = '', errors: list = None, data = None):
    """
    Gera uma resposta padronizada para a API.
    """
    return {
        "success": success,
        "message": message,
        "errors": errors or [],
        "data": data
    }
