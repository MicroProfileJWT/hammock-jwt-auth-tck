/*
 * Copyright (c) 2016-2017 Contributors to the Eclipse Foundation
 *
 *  See the NOTICE file(s) distributed with this work for additional
 *  information regarding copyright ownership.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  You may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package ws.ament.hammock.mpjwttck;

import java.security.PublicKey;
import java.util.Map;

import org.eclipse.microprofile.jwt.JWTPrincipal;
import org.eclipse.microprofile.jwt.tck.util.ITokenParser;
import ws.ament.hammock.jwt.processor.DefaultValidatingJWTProcessor;

public class TCKTokenParser implements ITokenParser {

    /**
     * Create our JWTPrincipal implementation
     * @param bearerToken - the raw bearer token from auth header
     * @param issuer - the issuer to validate against
     * @param publicKey - the public key of the expected signer
     * @return Hammock JWTPrincipal
     * @throws Exception on unexpected error
     */
    @Override
    public JWTPrincipal parse(String bearerToken, String issuer, PublicKey publicKey) throws Exception {
        DefaultValidatingJWTProcessor processor = new DefaultValidatingJWTProcessor();
        // TODO: need way to set JWSKeySelector to use argument public key...
        Map<String, Object> claims = processor.process(bearerToken);
        ws.ament.hammock.jwt.JWTPrincipal impl = new ws.ament.hammock.jwt.JWTPrincipal(claims, bearerToken);
        return impl;
    }

}
