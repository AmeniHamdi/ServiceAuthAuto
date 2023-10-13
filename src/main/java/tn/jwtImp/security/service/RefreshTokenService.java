package tn.jwtImp.security.service;

import tn.jwtImp.security.entities.RefreshToken;
import tn.jwtImp.security.payload.request.RefreshTokenRequest;
import tn.jwtImp.security.payload.response.RefreshTokenResponse;

import java.util.Optional;

public interface RefreshTokenService {

    RefreshToken createRefreshToken(Long userId);
    RefreshToken verifyExpiration(RefreshToken token);
    Optional<RefreshToken> findByToken(String token);

    RefreshTokenResponse generateNewToken(RefreshTokenRequest request);

}
