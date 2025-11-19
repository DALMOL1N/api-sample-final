package br.edu.atitus.api_sample.controllers;

import java.util.List;
import java.util.UUID;

import org.springframework.beans.BeanUtils;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import br.edu.atitus.api_sample.dtos.RelatoDTO;
import br.edu.atitus.api_sample.entities.RelatoEntity;
import br.edu.atitus.api_sample.services.RelatoService;

@RestController
@RequestMapping("/ws/relato")
public class RelatoController {
	
	public final RelatoService service;

	public RelatoController(RelatoService service) {
		super();
		this.service = service;
	}	
	
	@DeleteMapping("/{id}")
	public ResponseEntity<String> delete(@PathVariable UUID id) throws Exception{
		service.deleteById(id);
		
		return ResponseEntity.ok("Relato excluído");
		
	}
	
	@PostMapping
		public ResponseEntity<RelatoEntity> save(@RequestBody RelatoDTO dto) throws Exception {
			RelatoEntity relato = new RelatoEntity();
			BeanUtils.copyProperties(dto, relato);
			
			service.save(relato);
			
			return ResponseEntity.status(201).body(relato);
		}
		
		@PutMapping("/{id}")
		public ResponseEntity<RelatoEntity> update(@PathVariable UUID id, @RequestBody RelatoDTO dto) throws Exception {
			RelatoEntity relato = new RelatoEntity();
			BeanUtils.copyProperties(dto, relato);
			
			service.update(id, relato);
			
			return ResponseEntity.ok(relato);
		}

	@GetMapping
	public ResponseEntity<List<RelatoEntity>> findAll(){
		var lista = service.findAll();
		return ResponseEntity.ok(lista);
	}
	
	@ExceptionHandler(value = Exception.class)
	public ResponseEntity<String> handlerException(Exception ex) {
		String message = ex.getMessage().replaceAll("\r\n", "");
		return ResponseEntity.badRequest().body(message);
	}
	
}
