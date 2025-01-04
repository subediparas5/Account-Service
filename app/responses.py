from fastapi.responses import JSONResponse


class JsonResponse(JSONResponse):
    def __init__(self, *args, **kwargs):
        super().__init__(
            *args,
            **kwargs,
        )
        self.headers["Server"] = "Accounts API"
