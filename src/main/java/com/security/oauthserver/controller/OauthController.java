package com.security.oauthserver.controller;

import com.security.oauthserver.dto.UserDto;
import com.security.oauthserver.service.MyUserDetailsService;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import com.security.oauthserver.entity.User;
import java.security.Principal;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class OauthController {

    private MyUserDetailsService userDetailsService;

    public OauthController(MyUserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @GetMapping("/details")
    public String getDetails(Principal principal)
    {
        return principal.getName();
    }

    @GetMapping("/oauth2/code/internal-client")
    public ResponseEntity<Map<String,String>> getAuthorizationCode(@RequestParam("code") String authorizationCode){
        if(authorizationCode==null || authorizationCode.isEmpty()){
            return new ResponseEntity<>(Map.of("AuthorizationCode","No Authorization Code"), HttpStatusCode.valueOf(500));
        }
        return ResponseEntity.ok(Map.of("AuthorizationCode",authorizationCode));
    }

    @GetMapping("/user")
    public ResponseEntity<UserDetails> getUserByEmailId(){
        UserDetails userDetails=userDetailsService.loadUserByUsername("arun.com");
        return ResponseEntity.ok(userDetails);
    }

    @PostMapping("/user")
    public ResponseEntity<User> addUser(@RequestBody UserDto userDto){
        return ResponseEntity.ok(userDetailsService.registerNewUserAccount(userDto));
    }
}
