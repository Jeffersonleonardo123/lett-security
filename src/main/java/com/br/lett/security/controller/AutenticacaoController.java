package com.br.lett.security.controller;

import com.br.lett.security.dto.DataAutenticationDto;
import com.br.lett.security.infra.DataTokenJWT;
import com.br.lett.security.repository.UserRepository;
import com.br.lett.security.service.AutenticacaoService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/authentication")
public class AutenticacaoController {

    @Autowired
    private UserRepository repository;

    @Autowired
    private AutenticacaoService autenticacaoService;

    @PostMapping(path="/getToken")
    public ResponseEntity getToken(@RequestBody @Valid DataAutenticationDto dados) {
/*
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        String senha = encoder.encode("123");
*/

        String tokenJWT = autenticacaoService.getTokenJWT(dados);

        return ResponseEntity.ok(new DataTokenJWT(tokenJWT));
    }



    @PostMapping(path="/validatedToken")
    public ResponseEntity validatedToken(HttpServletRequest request) {

        var tokenValidatedReturnDto = autenticacaoService.validatedToken(request);

        return ResponseEntity.ok(tokenValidatedReturnDto);
    }


}
