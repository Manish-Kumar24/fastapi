import logging
logger = logging.getLogger("fastapi")

import inspect
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import cached_property, partial
from typing import Any, Literal

from fastapi._compat import ModelField
from fastapi.security.base import SecurityBase
from fastapi.types import DependencyCacheKey

if sys.version_info >= (3, 13):  # pragma: no cover
    from inspect import iscoroutinefunction
else:  # pragma: no cover
    from asyncio import iscoroutinefunction


def _unwrapped_call(call: Callable[..., Any] | None) -> Any:
    if call is None:
        return call  # pragma: no cover
    unwrapped = inspect.unwrap(_impartial(call))
    return unwrapped


def _impartial(func: Callable[..., Any]) -> Callable[..., Any]:
    while isinstance(func, partial):
        func = func.func
    return func


@dataclass
class Dependant:
    path_params: list[ModelField] = field(default_factory=list)
    query_params: list[ModelField] = field(default_factory=list)
    header_params: list[ModelField] = field(default_factory=list)
    cookie_params: list[ModelField] = field(default_factory=list)
    body_params: list[ModelField] = field(default_factory=list)
    dependencies: list["Dependant"] = field(default_factory=list)
    name: str | None = None
    call: Callable[..., Any] | None = None
    request_param_name: str | None = None
    websocket_param_name: str | None = None
    http_connection_param_name: str | None = None
    response_param_name: str | None = None
    background_tasks_param_name: str | None = None
    security_scopes_param_name: str | None = None
    own_oauth_scopes: list[str] | None = None
    parent_oauth_scopes: list[str] | None = None
    use_cache: bool = True
    path: str | None = None
    scope: Literal["function", "request"] | None = None

    @cached_property
    def oauth_scopes(self) -> list[str]:
        scopes = self.parent_oauth_scopes.copy() if self.parent_oauth_scopes else []
        # This doesn't use a set to preserve order, just in case
        for scope in self.own_oauth_scopes or []:
            if scope not in scopes:
                scopes.append(scope)
        return scopes

    @cached_property
    def cache_key(self) -> DependencyCacheKey:
        scopes_for_cache = (
            tuple(sorted(set(self.oauth_scopes or []))) if self._uses_scopes else ()
        )
        return (
            self.call,
            scopes_for_cache,
            self.computed_scope or "",
        )

    @cached_property
    def _uses_scopes(self) -> bool:
        if self.own_oauth_scopes:
            return True
        if self.security_scopes_param_name is not None:
            return True
        if self._is_security_scheme:
            return True
        for sub_dep in self.dependencies:
            if sub_dep._uses_scopes:
                return True
        return False

    @cached_property
    def _is_security_scheme(self) -> bool:
        if self.call is None:
            return False  # pragma: no cover
        unwrapped = _unwrapped_call(self.call)
        return isinstance(unwrapped, SecurityBase)

    # Mainly to get the type of SecurityBase, but it's the same self.call
    @cached_property
    def _security_scheme(self) -> SecurityBase:
        unwrapped = _unwrapped_call(self.call)
        assert isinstance(unwrapped, SecurityBase)
        return unwrapped

    @cached_property
    def _security_dependencies(self) -> list["Dependant"]:
        security_deps = [dep for dep in self.dependencies if dep._is_security_scheme]
        return security_deps

    @cached_property
    def is_gen_callable(self) -> bool:
        if self.call is None:
            return False  # pragma: no cover
        if inspect.isgeneratorfunction(
            _impartial(self.call)
        ) or inspect.isgeneratorfunction(_unwrapped_call(self.call)):
            return True
        if inspect.isclass(_unwrapped_call(self.call)):
            return False
        dunder_call = getattr(_impartial(self.call), "__call__", None)  # noqa: B004
        if dunder_call is None:
            return False  # pragma: no cover
        if inspect.isgeneratorfunction(
            _impartial(dunder_call)
        ) or inspect.isgeneratorfunction(_unwrapped_call(dunder_call)):
            return True
        dunder_unwrapped_call = getattr(_unwrapped_call(self.call), "__call__", None)  # noqa: B004
        if dunder_unwrapped_call is None:
            return False  # pragma: no cover
        if inspect.isgeneratorfunction(
            _impartial(dunder_unwrapped_call)
        ) or inspect.isgeneratorfunction(_unwrapped_call(dunder_unwrapped_call)):
            return True
        return False

    @cached_property
    def is_async_gen_callable(self) -> bool:
        if self.call is None:
            return False  # pragma: no cover
        if inspect.isasyncgenfunction(
            _impartial(self.call)
        ) or inspect.isasyncgenfunction(_unwrapped_call(self.call)):
            return True
        if inspect.isclass(_unwrapped_call(self.call)):
            return False
        dunder_call = getattr(_impartial(self.call), "__call__", None)  # noqa: B004
        if dunder_call is None:
            return False  # pragma: no cover
        if inspect.isasyncgenfunction(
            _impartial(dunder_call)
        ) or inspect.isasyncgenfunction(_unwrapped_call(dunder_call)):
            return True
        dunder_unwrapped_call = getattr(_unwrapped_call(self.call), "__call__", None)  # noqa: B004
        if dunder_unwrapped_call is None:
            return False  # pragma: no cover
        if inspect.isasyncgenfunction(
            _impartial(dunder_unwrapped_call)
        ) or inspect.isasyncgenfunction(_unwrapped_call(dunder_unwrapped_call)):
            return True
        return False

    @cached_property
    def is_coroutine_callable(self) -> bool:
        if self.call is None:
            return False  # pragma: no cover
        if inspect.isroutine(_impartial(self.call)) and iscoroutinefunction(
            _impartial(self.call)
        ):
            return True
        if inspect.isroutine(_unwrapped_call(self.call)) and iscoroutinefunction(
            _unwrapped_call(self.call)
        ):
            return True
        if inspect.isclass(_unwrapped_call(self.call)):
            return False
        dunder_call = getattr(_impartial(self.call), "__call__", None)  # noqa: B004
        if dunder_call is None:
            return False  # pragma: no cover
        if iscoroutinefunction(_impartial(dunder_call)) or iscoroutinefunction(
            _unwrapped_call(dunder_call)
        ):
            return True
        dunder_unwrapped_call = getattr(_unwrapped_call(self.call), "__call__", None)  # noqa: B004
        if dunder_unwrapped_call is None:
            return False  # pragma: no cover
        if iscoroutinefunction(
            _impartial(dunder_unwrapped_call)
        ) or iscoroutinefunction(_unwrapped_call(dunder_unwrapped_call)):
            return True
        return False

    @cached_property
    def computed_scope(self) -> str | None:
        if self.scope:
            return self.scope
        if self.is_gen_callable or self.is_async_gen_callable:
            return "request"
        return None

from collections.abc import Callable, Mapping
from typing import (
    Annotated,
    Any,
    BinaryIO,
    TypeVar,
    cast,
)

from annotated_doc import Doc
from pydantic import GetJsonSchemaHandler
from starlette.datastructures import URL as URL  # noqa: F401
from starlette.datastructures import Address as Address  # noqa: F401
from starlette.datastructures import FormData as FormData  # noqa: F401
from starlette.datastructures import Headers as Headers  # noqa: F401
from starlette.datastructures import QueryParams as QueryParams  # noqa: F401
from starlette.datastructures import State as State  # noqa: F401
from starlette.datastructures import UploadFile as StarletteUploadFile


class UploadFile(StarletteUploadFile):
    """
    A file uploaded in a request.

    Define it as a *path operation function* (or dependency) parameter.

    If you are using a regular `def` function, you can use the `upload_file.file`
    attribute to access the raw standard Python file (blocking, not async), useful and
    needed for non-async code.

    Read more about it in the
    [FastAPI docs for Request Files](https://fastapi.tiangolo.com/tutorial/request-files/).

    ## Example

    ```python
    from typing import Annotated

    from fastapi import FastAPI, File, UploadFile

    app = FastAPI()


    @app.post("/files/")
    async def create_file(file: Annotated[bytes, File()]):
        return {"file_size": len(file)}


    @app.post("/uploadfile/")
    async def create_upload_file(file: UploadFile):
        return {"filename": file.filename}
    ```
    """

    file: Annotated[
        BinaryIO,
        Doc("The standard Python file object (non-async)."),
    ]
    filename: Annotated[str | None, Doc("The original file name.")]
    size: Annotated[int | None, Doc("The size of the file in bytes.")]
    headers: Annotated[Headers, Doc("The headers of the request.")]
    content_type: Annotated[
        str | None, Doc("The content type of the request, from the headers.")
    ]

    async def write(
        self,
        data: Annotated[
            bytes,
            Doc(
                """
                The bytes to write to the file.
                """
            ),
        ],
    ) -> None:
        """
        Write some bytes to the file.

        You normally wouldn't use this from a file you read in a request.

        To be awaitable, compatible with async, this is run in threadpool.
        """
        return await super().write(data)

    async def read(
        self,
        size: Annotated[
            int,
            Doc(
                """
                The number of bytes to read from the file.
                """
            ),
        ] = -1,
    ) -> bytes:
        """
        Read some bytes from the file.

        To be awaitable, compatible with async, this is run in threadpool.
        """
        return await super().read(size)

    async def seek(
        self,
        offset: Annotated[
            int,
            Doc(
                """
                The position in bytes to seek to in the file.
                """
            ),
        ],
    ) -> None:
        """
        Move to a position in the file.

        Any next read or write will be done from that position.

        To be awaitable, compatible with async, this is run in threadpool.
        """
        return await super().seek(offset)

    async def close(self) -> None:
        """
        Close the file.

        To be awaitable, compatible with async, this is run in threadpool.
        """
        return await super().close()

    @classmethod
    def _validate(cls, __input_value: Any, _: Any) -> "UploadFile":
        if not isinstance(__input_value, StarletteUploadFile):
            raise ValueError(f"Expected UploadFile, received: {type(__input_value)}")
        return cast(UploadFile, __input_value)

    @classmethod
    def __get_pydantic_json_schema__(
        cls, core_schema: Mapping[str, Any], handler: GetJsonSchemaHandler
    ) -> dict[str, Any]:
        return {"type": "string", "contentMediaType": "application/octet-stream"}

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source: type[Any], handler: Callable[[Any], Mapping[str, Any]]
    ) -> Mapping[str, Any]:
        from ._compat.v2 import with_info_plain_validator_function

        return with_info_plain_validator_function(cls._validate)


class DefaultPlaceholder:
    """
    You shouldn't use this class directly.

    It's used internally to recognize when a default value has been overwritten, even
    if the overridden default value was truthy.
    """

    def __init__(self, value: Any):
        self.value = value

    def __bool__(self) -> bool:
        return bool(self.value)

    def __eq__(self, o: object) -> bool:
        return isinstance(o, DefaultPlaceholder) and o.value == self.value


DefaultType = TypeVar("DefaultType")


def Default(value: DefaultType) -> DefaultType:
    """
    You shouldn't use this function directly.

    It's used internally to recognize when a default value has been overwritten, even
    if the overridden default value was truthy.
    """
    return DefaultPlaceholder(value)  # type: ignore

import dataclasses
import datetime
from collections import defaultdict, deque
from collections.abc import Callable
from decimal import Decimal
from enum import Enum
from ipaddress import (
    IPv4Address,
    IPv4Interface,
    IPv4Network,
    IPv6Address,
    IPv6Interface,
    IPv6Network,
)
from pathlib import Path, PurePath
from re import Pattern
from types import GeneratorType
from typing import Annotated, Any
from uuid import UUID

from annotated_doc import Doc
from fastapi.exceptions import PydanticV1NotSupportedError
from fastapi.types import IncEx
from pydantic import BaseModel
from pydantic.color import Color
from pydantic.networks import AnyUrl, NameEmail
from pydantic.types import SecretBytes, SecretStr
from pydantic_core import PydanticUndefinedType

from ._compat import (
    Url,
    is_pydantic_v1_model_instance,
)


# Taken from Pydantic v1 as is
def isoformat(o: datetime.date | datetime.time) -> str:
    return o.isoformat()


# Adapted from Pydantic v1
# TODO: pv2 should this return strings instead?
def decimal_encoder(dec_value: Decimal) -> int | float:
    """
    Encodes a Decimal as int if there's no exponent, otherwise float

    This is useful when we use ConstrainedDecimal to represent Numeric(x,0)
    where an integer (but not int typed) is used. Encoding this as a float
    results in failed round-tripping between encode and parse.
    Our Id type is a prime example of this.

    >>> decimal_encoder(Decimal("1.0"))
    1.0

    >>> decimal_encoder(Decimal("1"))
    1

    >>> decimal_encoder(Decimal("NaN"))
    nan
    """
    exponent = dec_value.as_tuple().exponent
    if isinstance(exponent, int) and exponent >= 0:
        return int(dec_value)
    else:
        return float(dec_value)


ENCODERS_BY_TYPE: dict[type[Any], Callable[[Any], Any]] = {
    bytes: lambda o: o.decode(),
    Color: str,
    datetime.date: isoformat,
    datetime.datetime: isoformat,
    datetime.time: isoformat,
    datetime.timedelta: lambda td: td.total_seconds(),
    Decimal: decimal_encoder,
    Enum: lambda o: o.value,
    frozenset: list,
    deque: list,
    GeneratorType: list,
    IPv4Address: str,
    IPv4Interface: str,
    IPv4Network: str,
    IPv6Address: str,
    IPv6Interface: str,
    IPv6Network: str,
    NameEmail: str,
    Path: str,
    Pattern: lambda o: o.pattern,
    SecretBytes: str,
    SecretStr: str,
    set: list,
    UUID: str,
    Url: str,
    AnyUrl: str,
}


def generate_encoders_by_class_tuples(
    type_encoder_map: dict[Any, Callable[[Any], Any]],
) -> dict[Callable[[Any], Any], tuple[Any, ...]]:
    encoders_by_class_tuples: dict[Callable[[Any], Any], tuple[Any, ...]] = defaultdict(
        tuple
    )
    for type_, encoder in type_encoder_map.items():
        encoders_by_class_tuples[encoder] += (type_,)
    return encoders_by_class_tuples


encoders_by_class_tuples = generate_encoders_by_class_tuples(ENCODERS_BY_TYPE)


def jsonable_encoder(
    obj: Annotated[
        Any,
        Doc(
            """
            The input object to convert to JSON.
            """
        ),
    ],
    include: Annotated[
        IncEx | None,
        Doc(
            """
            Pydantic's `include` parameter, passed to Pydantic models to set the
            fields to include.
            """
        ),
    ] = None,
    exclude: Annotated[
        IncEx | None,
        Doc(
            """
            Pydantic's `exclude` parameter, passed to Pydantic models to set the
            fields to exclude.
            """
        ),
    ] = None,
    by_alias: Annotated[
        bool,
        Doc(
            """
            Pydantic's `by_alias` parameter, passed to Pydantic models to define if
            the output should use the alias names (when provided) or the Python
            attribute names. In an API, if you set an alias, it's probably because you
            want to use it in the result, so you probably want to leave this set to
            `True`.
            """
        ),
    ] = True,
    exclude_unset: Annotated[
        bool,
        Doc(
            """
            Pydantic's `exclude_unset` parameter, passed to Pydantic models to define
            if it should exclude from the output the fields that were not explicitly
            set (and that only had their default values).
            """
        ),
    ] = False,
    exclude_defaults: Annotated[
        bool,
        Doc(
            """
            Pydantic's `exclude_defaults` parameter, passed to Pydantic models to define
            if it should exclude from the output the fields that had the same default
            value, even when they were explicitly set.
            """
        ),
    ] = False,
    exclude_none: Annotated[
        bool,
        Doc(
            """
            Pydantic's `exclude_none` parameter, passed to Pydantic models to define
            if it should exclude from the output any fields that have a `None` value.
            """
        ),
    ] = False,
    custom_encoder: Annotated[
        dict[Any, Callable[[Any], Any]] | None,
        Doc(
            """
            Pydantic's `custom_encoder` parameter, passed to Pydantic models to define
            a custom encoder.
            """
        ),
    ] = None,
    sqlalchemy_safe: Annotated[
        bool,
        Doc(
            """
            Exclude from the output any fields that start with the name `_sa`.

            This is mainly a hack for compatibility with SQLAlchemy objects, they
            store internal SQLAlchemy-specific state in attributes named with `_sa`,
            and those objects can't (and shouldn't be) serialized to JSON.
            """
        ),
    ] = True,
) -> Any:
    """
    Convert any object to something that can be encoded in JSON.

    This is used internally by FastAPI to make sure anything you return can be
    encoded as JSON before it is sent to the client.

    You can also use it yourself, for example to convert objects before saving them
    in a database that supports only JSON.

    Read more about it in the
    [FastAPI docs for JSON Compatible Encoder](https://fastapi.tiangolo.com/tutorial/encoder/).
    """
    custom_encoder = custom_encoder or {}
    if custom_encoder:
        if type(obj) in custom_encoder:
            return custom_encoder[type(obj)](obj)
        else:
            for encoder_type, encoder_instance in custom_encoder.items():
                if isinstance(obj, encoder_type):
                    return encoder_instance(obj)
    if include is not None and not isinstance(include, (set, dict)):
        include = set(include)  # type: ignore[assignment]
    if exclude is not None and not isinstance(exclude, (set, dict)):
        exclude = set(exclude)  # type: ignore[assignment]
    if isinstance(obj, BaseModel):
        obj_dict = obj.model_dump(
            mode="json",
            include=include,
            exclude=exclude,
            by_alias=by_alias,
            exclude_unset=exclude_unset,
            exclude_none=exclude_none,
            exclude_defaults=exclude_defaults,
        )
        return jsonable_encoder(
            obj_dict,
            exclude_none=exclude_none,
            exclude_defaults=exclude_defaults,
            sqlalchemy_safe=sqlalchemy_safe,
        )
    if dataclasses.is_dataclass(obj):
        assert not isinstance(obj, type)
        obj_dict = dataclasses.asdict(obj)
        return jsonable_encoder(
            obj_dict,
            include=include,
            exclude=exclude,
            by_alias=by_alias,
            exclude_unset=exclude_unset,
            exclude_defaults=exclude_defaults,
            exclude_none=exclude_none,
            custom_encoder=custom_encoder,
            sqlalchemy_safe=sqlalchemy_safe,
        )
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, PurePath):
        return str(obj)
    if isinstance(obj, (str, int, float, type(None))):
        return obj
    if isinstance(obj, PydanticUndefinedType):
        return None
    if isinstance(obj, dict):
        encoded_dict = {}
        allowed_keys = set(obj.keys())
        if include is not None:
            allowed_keys &= set(include)
        if exclude is not None:
            allowed_keys -= set(exclude)
        for key, value in obj.items():
            if (
                (
                    not sqlalchemy_safe
                    or (not isinstance(key, str))
                    or (not key.startswith("_sa"))
                )
                and (value is not None or not exclude_none)
                and key in allowed_keys
            ):
                encoded_key = jsonable_encoder(
                    key,
                    by_alias=by_alias,
                    exclude_unset=exclude_unset,
                    exclude_none=exclude_none,
                    custom_encoder=custom_encoder,
                    sqlalchemy_safe=sqlalchemy_safe,
                )
                encoded_value = jsonable_encoder(
                    value,
                    by_alias=by_alias,
                    exclude_unset=exclude_unset,
                    exclude_none=exclude_none,
                    custom_encoder=custom_encoder,
                    sqlalchemy_safe=sqlalchemy_safe,
                )
                encoded_dict[encoded_key] = encoded_value
        return encoded_dict
    if isinstance(obj, (list, set, frozenset, GeneratorType, tuple, deque)):
        encoded_list = []
        for item in obj:
            encoded_list.append(
                jsonable_encoder(
                    item,
                    include=include,
                    exclude=exclude,
                    by_alias=by_alias,
                    exclude_unset=exclude_unset,
                    exclude_defaults=exclude_defaults,
                    exclude_none=exclude_none,
                    custom_encoder=custom_encoder,
                    sqlalchemy_safe=sqlalchemy_safe,
                )
            )
        return encoded_list

    if type(obj) in ENCODERS_BY_TYPE:
        return ENCODERS_BY_TYPE[type(obj)](obj)
    for encoder, classes_tuple in encoders_by_class_tuples.items():
        if isinstance(obj, classes_tuple):
            return encoder(obj)
    if is_pydantic_v1_model_instance(obj):
        raise PydanticV1NotSupportedError(
            "pydantic.v1 models are no longer supported by FastAPI."
            f" Please update the model {obj!r}."
        )
    try:
        data = dict(obj)
    except Exception as e:
        errors: list[Exception] = []
        errors.append(e)
        try:
            data = vars(obj)
        except Exception as e:
            errors.append(e)
            raise ValueError(errors) from e
    return jsonable_encoder(
        data,
        include=include,
        exclude=exclude,
        by_alias=by_alias,
        exclude_unset=exclude_unset,
        exclude_defaults=exclude_defaults,
        exclude_none=exclude_none,
        custom_encoder=custom_encoder,
        sqlalchemy_safe=sqlalchemy_safe,
    )
