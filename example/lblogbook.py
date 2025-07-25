from typing import BinaryIO, Optional, Sequence, Tuple, Union
from pyelog import ElogClient
import os

USERNAME = os.getenv("PYELOG_USERNAME", "default_user")     # <- Ask around
PASSWORD = os.getenv("PYELOG_PASSWORD", "default_password") # <- Ask around
SERVER = os.getenv("PYELOG_SERVER", "localhost")            # <- Ask around
PORT = int(os.getenv("PYELOG_PORT", 8080))                  # <- Ask around

client = ElogClient(
    SERVER,
    port=PORT,
    username=USERNAME,
    password=PASSWORD)

def create_log_entry(
    logbook: str,
    system: str,
    author: str,
    subject: str,
    message: str,
    attachments: Optional[Sequence[Tuple[str, Union[str, bytes, BinaryIO]]]] = None,
    suppress_email: bool = False,
    encoding: str = "plain",
    reply_to: Optional[int] = None,
    edit_id: Optional[int] = None,
):
    """Create a log entry in the specified logbook.
    Args:
        logbook: The name of the logbook.
        system: The system associated with the entry.
        author: The author of the entry.
        subject: The subject of the entry.
        message: The content of the entry.
        attachments: Optional attachments to include in the entry. Each attachment is a tuple of (filename, content).
        If content is a string, it will be treated as a file path. If it's bytes or a BinaryIO object, it will be treated as file content.
        suppress_email: Whether to suppress email notifications for this entry.
        encoding: The encoding type for the message. Defaults to "plain".
        reply_to: ID of the entry to which this is a reply, if any.
        edit_id: ID of the entry to edit, if applicable.

    Returns:
        Response from the ELOG server after submitting the entry.
    """
    attributes = {
        "author": author,
        "System": system,
        "Subject": subject
    }
    
    response = client.submit_entry(
        logbook=logbook,
        message=message,
        attributes=attributes,
        attachments=attachments,
        suppress_email=suppress_email,
        encoding=encoding,
        reply_to=reply_to,
        edit_id=edit_id
    )
    
    return response

if __name__ == "__main__":
    create_log_entry(
        logbook="TestLogbook",
        system="Test",
        author="Author", # <- Don't forget to set your author name. It's the only one that can delete the entry.
        subject="Test Entry",
        message="This is a test message.",
    )