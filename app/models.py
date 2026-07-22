from pydantic import BaseModel, Field, field_validator


class UserRegister(BaseModel):
    username: str = Field(
        min_length=3,
        max_length=50,
    )

    password: str = Field(
        min_length=8,
        max_length=72,
    )

    @field_validator("password")
    @classmethod
    def validate_password_bytes(cls, password: str) -> str:
        """
        Bcrypt accepts a maximum of 72 bytes.

        Some Unicode characters use more than one byte, so checking
        character count alone is not enough.
        """

        if len(password.encode("utf-8")) > 72:
            raise ValueError(
                "Password must not exceed 72 bytes."
            )

        return password


class UserLogin(BaseModel):
    username: str

    password: str

    @field_validator("password")
    @classmethod
    def validate_password_bytes(cls, password: str) -> str:
        if len(password.encode("utf-8")) > 72:
            raise ValueError(
                "Password must not exceed 72 bytes."
            )

        return password


class TokenResponse(BaseModel):
    access_token: str
    token_type: str


class IncidentCreate(BaseModel):
    """
    Defines the information a client must provide
    when creating a new incident.
    """

    title: str = Field(
        ...,
        min_length=3,
        max_length=100,
        examples=["Virtual machine CPU usage is high"],
    )

    description: str = Field(
        ...,
        min_length=5,
        max_length=500,
        examples=["CPU usage remained above 90% for ten minutes."],
    )

    severity: str = Field(
        ...,
        examples=["high"],
    )


class IncidentResponse(BaseModel):
    """
    Defines the complete incident returned by the API.
    """

    id: int
    title: str
    description: str
    severity: str
    status: str
    created_by: str
