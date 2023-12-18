"""SMTP tests"""

from __future__ import annotations

import logging
import socket
import smtplib
from ssl import SSLError, SSLContext, create_default_context

import timeout_decorator
from expiringdict import ExpiringDict


"""Copyright 2019-2023 Sean Whalen

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License."""


class SMTPError(Exception):
    """Raised when SMTP error occurs"""


@timeout_decorator.timeout(5, timeout_exception=SMTPError,
                           exception_message="Connection timed out")
def test_tls(hostname: str, ssl_context: SSLContext = None,
             cache: ExpiringDict = None) -> bool:
    """
    Attempt to connect to an SMTP server port 465 and validate TLS/SSL support

    Args:
        hostname (str): The hostname
        cache (ExpiringDict): Cache storage
        ssl_context (SSLContext): A SSL context

    Returns:
        bool: TLS supported
    """
    tls = False
    if cache:
        cached_result = cache.get(hostname)
        if cached_result is not None:
            if cached_result["error"] is not None:
                raise SMTPError(cached_result["error"])
            return cached_result["tls"]
    if ssl_context is None:
        ssl_context = create_default_context()
    logging.debug(f"Testing TLS/SSL on {hostname}")
    try:
        server = smtplib.SMTP_SSL(hostname, context=ssl_context)
        server.ehlo_or_helo_if_needed()
        tls = True
        try:
            server.quit()
            server.close()
        except Exception as e:
            logging.debug(e)
        finally:
            return tls

    except socket.gaierror:
        error = "DNS resolution failed"
        if cache:
            cache[hostname] = dict(tls=False, error=error)
        raise SMTPError(error)
    except ConnectionRefusedError:
        error = "Connection refused"
        if cache:
            cache[hostname] = dict(tls=False, error=error)
        raise SMTPError(error)
    except ConnectionResetError:
        error = "Connection reset"
        if cache:
            cache[hostname] = dict(tls=False, error=error)
        raise SMTPError(error)
    except ConnectionAbortedError:
        error = "Connection aborted"
        if cache:
            cache[hostname] = dict(tls=False, error=error)
        raise SMTPError(error)
    except TimeoutError:
        error = "Connection timed out"
        if cache:
            cache[hostname] = dict(tls=False, error=error)
        raise SMTPError(error)
    except BlockingIOError as e:
        error = e.__str__()
        if cache:
            cache[hostname] = dict(tls=False, error=error)
        raise SMTPError(error)
    except SSLError as e:
        error = f"SSL error: {e}"
        if cache:
            cache[hostname] = dict(tls=False, error=error)
        raise SMTPError(error)
    except smtplib.SMTPConnectError as e:
        message = e.__str__()
        error_code = int(message.lstrip("(").split(",")[0])
        if error_code == 554:
            message = " SMTP error code 554 - Not allowed"
        else:
            message = f" SMTP error code {error_code}"
        error = f"Could not connect: {message}"
        if cache:
            cache[hostname] = dict(tls=False, error=error)
        raise SMTPError(error)
    except smtplib.SMTPHeloError as e:
        error = f"HELO error: {e}"
        if cache:
            cache[hostname] = dict(tls=False, error=error)
        raise SMTPError(error)
    except smtplib.SMTPException as e:
        error = e.__str__()
        error_code = error.lstrip("(").split(",")[0]
        error = f"SMTP error code {error_code}"
        if cache:
            cache[hostname] = dict(tls=False, error=error)
        raise SMTPError(error)
    except OSError as e:
        error = e.__str__()
        if cache:
            cache[hostname] = dict(tls=False, error=error)
        raise SMTPError(error)
    except Exception as e:
        error = e.__str__()
        if cache:
            cache[hostname] = dict(tls=False, error=error)
        raise SMTPError(error)
    finally:
        if cache:
            cache[hostname] = dict(tls=tls, error=None)
        return tls


@timeout_decorator.timeout(5, timeout_exception=SMTPError,
                           exception_message="Connection timed out")
def test_starttls(hostname: str,
                  ssl_context: SSLContext = None,
                  cache: ExpiringDict = None) -> bool:
    """
    Attempt to connect to an SMTP server and validate STARTTLS support

    Args:
        hostname (str): The hostname
        cache (ExpiringDict): Cache storage
        ssl_context: A SSL context

    Returns:
        bool: STARTTLS supported
    """
    starttls = False
    if cache:
        cached_result = cache.get(hostname)
        if cached_result is not None:
            if cached_result["error"] is not None:
                raise SMTPError(cached_result["error"])
            return cached_result["starttls"]
    if ssl_context is None:
        ssl_context = create_default_context()
    logging.debug(f"Testing STARTTLS on {hostname}")
    try:
        server = smtplib.SMTP(hostname)
        server.ehlo_or_helo_if_needed()
        if server.has_extn("starttls"):
            server.starttls(context=ssl_context)
            server.ehlo()
            starttls = True
        try:
            server.quit()
            server.close()
        except Exception as e:
            logging.debug(e)
        finally:
            if cache:
                cache[hostname] = dict(starttls=starttls, error=None)
            return starttls

    except socket.gaierror:
        error = "DNS resolution failed"
        if cache:
            cache[hostname] = dict(starttls=False, error=error)
        raise SMTPError(error)
    except ConnectionRefusedError:
        error = "Connection refused"
        if cache:
            cache[hostname] = dict(starttls=False, error=error)
        raise SMTPError(error)
    except ConnectionResetError:
        error = "Connection reset"
        if cache:
            cache[hostname] = dict(starttls=False, error=error)
        raise SMTPError(error)
    except ConnectionAbortedError:
        error = "Connection aborted"
        if cache:
            cache[hostname] = dict(starttls=False, error=error)
        raise SMTPError(error)
    except TimeoutError:
        error = "Connection timed out"
        if cache:
            cache[hostname] = dict(starttls=False, error=error)
        raise SMTPError(error)
    except BlockingIOError as e:
        error = e.__str__()
        if cache:
            cache[hostname] = dict(starttls=False, error=error)
        raise SMTPError(error)
    except SSLError as e:
        error = f"SSL error: {e}"
        if cache:
            cache[hostname] = dict(starttls=False, error=error)
        raise SMTPError(error)
    except smtplib.SMTPConnectError as e:
        message = e.__str__()
        error_code = int(message.lstrip("(").split(",")[0])
        if error_code == 554:
            message = " SMTP error code 554 - Not allowed"
        else:
            message = f" SMTP error code {error_code}"
        error = f"Could not connect: {message}"
        if cache:
            cache[hostname] = dict(starttls=False, error=error)
        raise SMTPError(error)
    except smtplib.SMTPHeloError as e:
        error = f"HELO error: {e}"
        if cache:
            cache[hostname] = dict(starttls=False, error=error)
        raise SMTPError(error)
    except smtplib.SMTPException as e:
        message = e.__str__()
        error_code = int(message.lstrip("(").split(",")[0])
        error = f"SMTP error code {error_code}"
        if cache:
            cache[hostname] = dict(starttls=False, error=error)
        raise SMTPError(error)
    except OSError as e:
        error = e.__str__()
        if cache:
            cache[hostname] = dict(starttls=False, error=error)
        raise SMTPError(error)
    except Exception as e:
        error = e.__str__()
        if cache:
            cache[hostname] = dict(starttls=False, error=error)
        raise SMTPError(error)
