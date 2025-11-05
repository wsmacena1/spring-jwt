package br.com.williansmacenajwt.springsecurityjwt.security;

import java.time.Instant;
import java.util.stream.Collectors;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

@Service // Indica que essa classe é um "serviço" do Spring (gerenciada automaticamente)
public class JwtService {

    // O JwtEncoder é o responsável por "fabricar" o token JWT
    private final JwtEncoder encoder;

    // Construtor: o Spring injeta automaticamente o encoder configurado
    public JwtService(JwtEncoder encoder) {
        this.encoder = encoder;
    }

    // Este método cria o token JWT com base no usuário autenticado
    public String generateToken(Authentication authentication) {

        // Pega o momento atual (quando o token está sendo criado)
        Instant now = Instant.now();

        // Define por quanto tempo o token será válido (10 horas = 36000 segundos)
        long expiry = 36000L;

        // Pega todas as permissões (roles) do usuário, e transforma em uma string:
        // exemplo: "ROLE_USER ROLE_ADMIN"
        String scope = authentication
                .getAuthorities() // lista de permissões do usuário
                .stream() // transforma em uma sequência processável
                .map(GrantedAuthority::getAuthority) // pega o nome da permissão (ex: "ROLE_USER")
                .collect(Collectors.joining(" ")); // junta tudo com espaço

        // Aqui montamos as informações (claims) que vão dentro do token
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("spring-security-jwt") // quem criou o token (pode ser o nome do seu app)
                .issuedAt(now) // quando o token foi criado
                .expiresAt(now.plusSeconds(expiry)) // quando ele expira
                .subject(authentication.getName()) // quem é o dono do token (usuário logado)
                .claim("scope", scope) // adiciona as permissões como um campo extra
                .build(); // finaliza o "molde" do token

        // Finalmente, usamos o encoder para transformar tudo isso em uma string JWT assinada
        // e retornamos o valor final do token
        return encoder.encode(JwtEncoderParameters.from(claims))
                .getTokenValue();
    }
}