package io.jans.jansfidoapp.services;

import java.util.Map;

import io.jans.jansfidoapp.models.assertion.option.AssertionOptionRequest;
import io.jans.jansfidoapp.models.assertion.option.AssertionOptionResponse;
import io.jans.jansfidoapp.models.assertion.result.AssertionResultRequest;
import io.jans.jansfidoapp.models.attestation.option.AttestationOptionRequest;
import io.jans.jansfidoapp.models.attestation.option.AttestationOptionResponse;
import io.jans.jansfidoapp.models.attestation.result.AttestationResultRequest;
import retrofit2.Call;
import retrofit2.http.Body;
import retrofit2.http.POST;
import retrofit2.http.Url;

public interface APIInterface {


    @POST
    Call<AttestationOptionResponse> attestationOption(@Body AttestationOptionRequest request, @Url String url);
    @POST
    Call<Map> attestationResult(@Body AttestationResultRequest request, @Url String url);
    @POST
    Call<AssertionOptionResponse> assertionOption(@Body AssertionOptionRequest request, @Url String url);
    @POST
    Call<Map> assertionResult(@Body AssertionResultRequest request, @Url String url);

}
