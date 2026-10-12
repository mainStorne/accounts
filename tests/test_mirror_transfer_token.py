from datetime import timedelta

from beanie import PydanticObjectId

from src.modules.tokens.repository import TokenRepository
from src.storages.mongo.models import User


def test_access_token_is_not_accepted_as_transfer_token():
    user = User.model_construct(id=PydanticObjectId("5eb7cf5a86d9755df3a6c593"))
    transfer_token = TokenRepository.create_mirror_transfer_token(user)
    access_token = TokenRepository.create_user_access_token(user)

    assert TokenRepository.verify_mirror_transfer_token(transfer_token) == str(user.id)
    assert TokenRepository.verify_mirror_transfer_token(access_token) is None
    assert TokenRepository.verify_mirror_transfer_token(transfer_token[:-4] + "abcd") is None


def test_expired_transfer_token_is_rejected():
    expired_token = TokenRepository._create_token(
        data={"uid": "5eb7cf5a86d9755df3a6c593"},
        expires_delta=timedelta(seconds=-1),
        aud=TokenRepository.MIRROR_TRANSFER_AUD,
    )
    assert TokenRepository.verify_mirror_transfer_token(expired_token) is None
