package tn.jwtImp.security.payload.request;

import lombok.Data;

@Data
public class RefreshTokenRequest {
    private String refreshToken;

}
