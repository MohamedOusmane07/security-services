package com.mohamed.securityservice.role;

import com.mohamed.securityservice.user.User;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;

import java.time.LocalDateTime;
import java.util.List;

@Entity
@AllArgsConstructor
@NoArgsConstructor
@Data

public class Role {

    @Id
    @GeneratedValue
    private Integer id;
    private String name;

    @CreatedDate
    @Column(updatable = false,nullable = false)
    private LocalDateTime createdAt;
    @LastModifiedDate
    @Column(insertable= false)
    private LocalDateTime updatedAt;

    @ManyToMany(mappedBy = "roles")
    private List<User> users;
}
