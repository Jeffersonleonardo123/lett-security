package com.br.lett.security.controller;

import com.br.lett.security.dto.DataAutenticationDto;
import com.br.lett.security.infra.DadosTokenJWT;
import com.br.lett.security.infra.TokenService;
import com.br.lett.security.model.User;
import com.br.lett.security.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping
public class AutenticacaoController {

    @Autowired
    private AuthenticationManager manager;

    @Autowired
    private TokenService tokenService;

    @Autowired
    private UserRepository repository;


    @PostMapping
    @RequestMapping("/login")
    public ResponseEntity efetuarLogin(@RequestBody @Valid DataAutenticationDto dados) {

        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        String senha = encoder.encode("123");

        var authenticationToken = new UsernamePasswordAuthenticationToken(dados.login(), dados.senha());
        var authentication = manager.authenticate(authenticationToken);

        var tokenJWT = tokenService.gerarToken((User) authentication.getPrincipal());

        return ResponseEntity.ok(new DadosTokenJWT(tokenJWT));
    }

    @PostMapping
    @RequestMapping("/validatedToken")
    public ResponseEntity validatedToken(HttpServletRequest request) {
        var token = recuperarToken(request);

        if (token != null) {
            var subject = tokenService.getSubject(token);
            var usuario = repository.findByLogin(subject);

            var authentication = new UsernamePasswordAuthenticationToken(usuario, null, usuario.getAuthorities());
        }

        return ResponseEntity.noContent().build();
    }

    @GetMapping
    @RequestMapping("/user")
    public ResponseEntity getUser(HttpServletRequest request) {
        var token = recuperarToken(request);

        if (token != null) {
            var subject = tokenService.getSubject(token);
            var usuario = repository.findByLogin(subject);

            var authentication = new UsernamePasswordAuthenticationToken(usuario, null, usuario.getAuthorities());
        }

        return ResponseEntity.ok(tokenService.getSubject(token));
    }

    @GetMapping
    @RequestMapping("/company")
    public ResponseEntity getCompany(HttpServletRequest request) {
        var token = recuperarToken(request);

        var companyName = tokenService.getCompany(token);
//        var authentication = new UsernamePasswordAuthenticationToken(usuario, null, usuario.getAuthorities());

        return ResponseEntity.ok(companyName);
    }

    private String recuperarToken(HttpServletRequest request) {
        var authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader != null) {
            return authorizationHeader.replace("Bearer ", "");
        }

        return null;
    }




}
