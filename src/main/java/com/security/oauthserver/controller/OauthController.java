package com.security.oauthserver.controller;

import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class OauthController {

    @GetMapping("/msg")
    public ResponseEntity<String> getEmployee(){
        return ResponseEntity.ok("Hey this is from oauth");
    }

    @GetMapping("/details")
    public String getDetails(Principal principal)
    {
        return principal.getName();
    }

    @GetMapping("/user/dashboard")
    public String userDashboard() {
        return "Welcome to User Dashboard!";
    }


    @GetMapping("/admin/dashboard")
    public String adminDashboard() {
        return "Welcome to Admin Dashboard!";
    }

    @GetMapping("/oauth2/code/internal-client")
    public ResponseEntity<Map<String,String>> getAuthorizationCode(@RequestParam("code") String authorizationCode){
        if(authorizationCode==null || authorizationCode.isEmpty()){
            return new ResponseEntity<>(Map.of("AuthorizationCode","No Authorization Code"), HttpStatusCode.valueOf(500));
        }
        return ResponseEntity.ok(Map.of("AuthorizationCode",authorizationCode));
    }

}
