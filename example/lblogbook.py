from typing import BinaryIO, Optional, Sequence, Tuple, Union

import os
USERNAME = os.getenv("PYELOG_USERNAME", "common")
PASSWORD = os.getenv("PYELOG_PASSWORD", "Common!")
SERVER = os.getenv("PYELOG_SERVER", "localhost")
PORT = int(os.getenv("PYELOG_PORT", 8080))
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
    """Create a log entry in the specified logbook."""
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
        author="Davide Nicotra",
        subject="Test Entry",
        message="This is a test message.",
    )