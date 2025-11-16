package br.edu.atitus.api_sample.controllers;

import org.springframework.beans.BeanUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import jakarta.validation.Valid;

import br.edu.atitus.api_sample.components.JWTUtils;
import br.edu.atitus.api_sample.dtos.SigninDTO;
import br.edu.atitus.api_sample.dtos.SignupDTO;
import br.edu.atitus.api_sample.dtos.LoginResponseDTO;
import br.edu.atitus.api_sample.entities.UserEntity;
import br.edu.atitus.api_sample.entities.UserType;
import br.edu.atitus.api_sample.services.UserService;

@RestController
@RequestMapping("/auth")
public class AuthController {
	
	private final UserService service;
	private final AuthenticationConfiguration authConfig;
	
	// Injeção de dependência via método construtor
	public AuthController(UserService service, AuthenticationConfiguration authConfig) {
		super();
		this.service = service;
		this.authConfig = authConfig;
	}
	
@PostMapping("/signin")
    public ResponseEntity<LoginResponseDTO> signin(@RequestBody SigninDTO signin) {
        try {
            authConfig.getAuthenticationManager()
                .authenticate(new UsernamePasswordAuthenticationToken(signin.email(), signin.password()));

            UserEntity user = (UserEntity) service.findByEmail(signin.email()); 
            String nomeDoUsuario = user.getName(); //
            String emailDoUsuario = user.getEmail();
            

            String token = JWTUtils.generateToken(emailDoUsuario, nomeDoUsuario);

            return ResponseEntity.ok(new LoginResponseDTO(token, nomeDoUsuario)); 

        } catch (AuthenticationException e) {
            throw new RuntimeException("Email ou senha inválidos", e);
        } catch (Exception e) {
            throw new RuntimeException("Erro ao processar login", e);
        }
    }
	

	@PostMapping("/signup")
	public ResponseEntity<UserEntity> signup(@Valid @RequestBody SignupDTO dto) throws Exception{
		// Criamos a entidade (novo objeto)
		UserEntity user = new UserEntity();
		// Copia-se as propriedades da DTO para a entidade
		BeanUtils.copyProperties(dto, user);
		// Seta-se os valores que não vieram no DTO
		user.setType(UserType.Common);
		
		service.save(user);
		
		return ResponseEntity.status(HttpStatus.CREATED).body(user);
	}
	
	@ExceptionHandler(value = Exception.class)
	public ResponseEntity<String> handlerException(Exception ex) {
		String message = ex.getMessage().replaceAll("\r\n", "");
		return ResponseEntity.badRequest().body(message);
	}
}
