@id("AcrsWrite")
permit (
  principal is Jans::Workload,
  action in [Jans::Action::"POST"],
  resource == Jans::HTTP_Request::"/jans-config-api/api/v1/acrs"
)
when {
  principal has access_token.scope &&
  principal.access_token.scope.containsAny(
  ["https://jans.io/oauth/config/acrs.readonly","https://jans.io/oauth/config/acrs.write",
  "https://jans.io/oauth/config/read-all"])
};