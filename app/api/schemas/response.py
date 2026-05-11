from typing import Any, Generic, TypeVar, Optional, List
from pydantic import BaseModel, Field

# Generic type for the data payload
T = TypeVar("T")

class ErrorDetail(BaseModel):
    """
    Detailed error format for validation or specific field errors.
    """
    loc: Optional[List[str]] = Field(default=None, description="Location of the error (e.g., ['body', 'email'])")
    msg: str = Field(..., description="Error message detail")
    type: str = Field(..., description="Error type identifier")

class APIResponse(BaseModel, Generic[T]):
    """
    Standardized single-resource or general API response wrapper.
    """
    status: str = Field(default="success", description="Indicates if the request was successful", examples=["success"])
    message: str = Field(default="Request processed successfully.", description="Human readable message")
    data: Optional[T] = Field(default=None, description="The actual data payload")

class PaginatedMetaData(BaseModel):
    """
    Metadata for pagination details.
    """
    page: int = Field(default=1, description="Current page number", ge=1)
    size: int = Field(default=10, description="Number of items per page", ge=1)
    total_items: int = Field(..., description="Total number of items across all pages", ge=0)
    total_pages: int = Field(..., description="Total number of pages available", ge=0)
    has_next: bool = Field(default=False, description="True if there's a subsequent page")
    has_previous: bool = Field(default=False, description="True if there's a preceding page")

class PaginatedAPIResponse(BaseModel, Generic[T]):
    """
    Standardized paginated API response wrapper.
    `data` will typically be a List[T].
    """
    status: str = Field(default="success", description="Indicates if the request was successful", examples=["success"])
    message: str = Field(default="Data retrieved successfully.", description="Human readable message")
    data: List[T] = Field(default_factory=list, description="List of items for the current page")
    meta: PaginatedMetaData = Field(..., description="Pagination metadata")

class APIErrorResponse(BaseModel):
    """
    Standardized error response wrapper.
    """
    status: str = Field(default="error", description="Indicates that an error occurred", examples=["error"])
    message: str = Field(..., description="A clear, human-readable error summary")
    error_code: Optional[str] = Field(default=None, description="Internal, specific error code for client matching", examples=["VALIDATION_ERROR", "NOT_FOUND", "INTERNAL_SERVER_ERROR"])
    details: Optional[List[ErrorDetail]] = Field(default=None, description="Detailed list of specific errors, useful for forms or specific validation reasons")