package com.br.lett.security.service;

import com.br.lett.security.dto.DataAutenticationDto;
import com.br.lett.security.dto.TokenValidatedReturnDto;
import com.br.lett.security.infra.TokenService;
import com.br.lett.security.model.User;
import com.br.lett.security.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

@Service
public class AutenticacaoService {

    @Autowired
    private UserRepository repository;

    @Autowired
    private AuthenticationManager manager;

    @Autowired
    private TokenService tokenService;

    public String getTokenJWT(DataAutenticationDto dataAutenticationDto) {
        String tokenJWT = "" ;
        try {
            Authentication authentication = getAuthentication(dataAutenticationDto);
            tokenJWT = tokenService.getToken((User) authentication.getPrincipal());

        } catch (BadCredentialsException e) {
            throw new RuntimeException("Usuário ou Senha inválidos! " + e.getMessage());
        } catch (InternalAuthenticationServiceException e){
            throw new RuntimeException("Usuário não cadastrado! " + e.getMessage());
        }

        return tokenJWT;
    }

    private Authentication getAuthentication(DataAutenticationDto dataAutenticationDto) {
        var authenticationToken = new UsernamePasswordAuthenticationToken(dataAutenticationDto.login(), dataAutenticationDto.password());
        var authentication = manager.authenticate(authenticationToken);
        return authentication;
    }

    public TokenValidatedReturnDto validatedToken(HttpServletRequest request){
        String token = buildToken(request);

        if ((token != null) && (!token.isBlank() || !token.isEmpty())) {

            var username = tokenService.getSubject(token);
            var user = repository.findByLogin(username);

            var authentication = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());

            return new TokenValidatedReturnDto(authentication.isAuthenticated(), username, tokenService.getCompany(token));

        } else {
            throw new RuntimeException("Não foi possível acessar os dados do token!");
        }

    }

    private String buildToken(HttpServletRequest request) {
        var authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader != null) {
            return authorizationHeader.replace("Bearer ", "");
        }

        return null;
    }
}
