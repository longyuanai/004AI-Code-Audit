class Demo {
    void query(HttpServletRequest request, Statement statement) throws Exception {
        String owner = request.getParameter("owner");
        statement.executeQuery("SELECT * FROM reports WHERE owner='" + owner + "'");
    }
}
