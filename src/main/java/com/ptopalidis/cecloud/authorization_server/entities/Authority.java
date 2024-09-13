package com.ptopalidis.cecloud.authorization_server.entities;


import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;


@Entity
@Setter
@Getter
@Table(name = "AUTHORITIES")
@AllArgsConstructor
@RequiredArgsConstructor
public class Authority {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private  String name;
}
