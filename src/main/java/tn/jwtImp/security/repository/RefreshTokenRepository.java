package tn.jwtImp.security.repository;

import tn.jwtImp.security.entities.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;


import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByToken(String token);

}
