package com.br.lett.security.dto;

public record TokenValidatedReturnDto(boolean authenticate, String user, String company ) {
}
