package no.ovalle.springsecurity.student;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("management/api/v1/students")
public class StudentManagementController {
    // Hard coding some placeholders
    private static List<Student> STUDENTS = Arrays.asList(
            new Student(1, "James Bond"),
            new Student(2, "Maria Jones"),
            new Student(3, "Anna Smith")
    );


    @GetMapping
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_ADMINTRAINEE')")
    public List<Student> getAllStudent() {
        System.out.println("Returning all students.");
        return STUDENTS;
    }

    @PostMapping
    @PreAuthorize("hasAuthority('student:write')")
    public void registerNewStudent(@RequestBody Student student) {
        Student s = new Student(student.getStudentId(), student.getStudentName());
        System.out.println(student);
        System.out.printf("New student: %s%n", s);
    }


    @DeleteMapping(path = {"{studentId}"})
    @PreAuthorize("hasAuthority('student:write')")
    public void  deleteStudent(@PathVariable("studentId") Integer studentId) {
        System.out.printf("Deleted: %s%n", studentId);
    }

    @PutMapping(path = {"{studentId}"})
    @PreAuthorize("hasAuthority('student:write')")
    public void updateStudent(@PathVariable("studentId") Integer studentId, @RequestBody Student student) {
        System.out.printf("Updated: %s %s%n", student, studentId);
    }

}
