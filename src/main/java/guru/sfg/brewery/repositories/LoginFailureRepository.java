package guru.sfg.brewery.repositories;

import guru.sfg.brewery.domain.security.LoginFailure;
import guru.sfg.brewery.domain.security.LoginSuccess;
import org.springframework.data.jpa.repository.JpaRepository;

public interface LoginFailureRepository  extends JpaRepository<LoginFailure, Integer> {
}