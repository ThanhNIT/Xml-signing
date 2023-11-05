package com.nitec.kz.payload;

public class SignXmlRequest {
    private String messageId;
    private String sessionId;
    private String requestContent;

    public SignXmlRequest(String messageId, String sessionId, String requestContent) {
        this.messageId = messageId;
        this.sessionId = sessionId;
        this.requestContent = requestContent;
    }

    public String getMessageId() {
        return messageId;
    }

    public void setMessageId(String messageId) {
        this.messageId = messageId;
    }

    public String getSessionId() {
        return sessionId;
    }

    public void setSessionId(String sessionId) {
        this.sessionId = sessionId;
    }

    public String getRequestContent() {
        return requestContent;
    }

    public void setRequestContent(String requestContent) {
        this.requestContent = requestContent;
    }
}
