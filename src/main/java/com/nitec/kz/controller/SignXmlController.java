package com.nitec.kz.controller;

import com.nitec.kz.payload.SignXmlRequest;
import com.nitec.kz.service.SignWssSec;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/sign-xml")
public class SignXmlController {

    @Autowired
    private SignWssSec signWssSec;

    @PostMapping
    public String signXml(@RequestBody SignXmlRequest signXmlRequest) {
        return signWssSec.signXml(signXmlRequest);
    }
}
