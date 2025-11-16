package br.edu.atitus.api_sample.dtos;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record SignupDTO(
		
		@NotBlank(message = "O nome é obrigatório")
		String name, 
		
		@NotBlank(message = "O e-mail é obrigatório")
		@Email(message = "O e-mail deve ser válido")
		@Pattern(regexp = "^[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\\.)+[A-Za-z]{2,6}$", 
                message = "O e-mail deve conter @ e dois ou mais domínios (ex: gmail.com, bol.com.br)")
		String email, 
		
		@NotBlank(message = "A senha é obrigatória")
		@Pattern(regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d).{8,}$", 
				message = "A senha deve conter pelo menos 8 caracteres, uma letra maiúscula, uma minúscula e um número.")
		String password) {

}
