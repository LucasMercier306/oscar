class ECSCLientException(Exception):
    pass


class ECSCLientRequestError(ECSCLientException):
    pass


class ECSCLientBadCredential(ECSCLientException):
    pass


class ECSClientSSHCommandError(ECSCLientException):
    pass
