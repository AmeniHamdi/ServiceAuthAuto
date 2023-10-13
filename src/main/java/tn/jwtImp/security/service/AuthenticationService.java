package tn.jwtImp.security.service;

import tn.jwtImp.security.payload.request.AuthenticationRequest;
import tn.jwtImp.security.payload.request.RegisterRequest;
import tn.jwtImp.security.payload.response.AuthenticationResponse;

public interface AuthenticationService {
    AuthenticationResponse register(RegisterRequest request);
    AuthenticationResponse authenticate(AuthenticationRequest request);
}
