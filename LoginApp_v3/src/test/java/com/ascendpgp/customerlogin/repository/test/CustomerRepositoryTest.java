package com.ascendpgp.customerlogin.repository.test;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Example;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.repository.query.FluentQuery;

import com.ascendpgp.customerlogin.model.CustomerEntity;
import com.ascendpgp.customerlogin.repository.CustomerRepository;

import java.util.List;
import java.util.ArrayList;
import java.util.Optional;
import java.util.function.Function;

import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class CustomerRepositoryTest {

    // Test implementation of CustomerRepository for testing default methods
    static class TestCustomerRepository implements CustomerRepository {
        private final CustomerEntity testCustomer;
        private final String testEmail;

        TestCustomerRepository(String testEmail) {
            this.testEmail = testEmail;
            this.testCustomer = new CustomerEntity();
            this.testCustomer.setEmail(testEmail);
        }

        @Override
        public CustomerEntity findByEmail(String email) {
            if (email.equals(testEmail)) {
                return testCustomer;
            }
            return null;
        }

        @Override
        public CustomerEntity findByUsername(String username) {
            return null;
        }

        @Override
        public CustomerEntity findByResetPasswordToken(String resetPasswordToken) {
            return null;
        }

        @Override
        public CustomerEntity findByVerificationToken(String token) {
            return null;
        }

        @Override
        public <S extends CustomerEntity> S insert(S entity) {
            return entity;
        }

        @Override
        public <S extends CustomerEntity> List<S> insert(Iterable<S> entities) {
            List<S> result = new ArrayList<>();
            entities.forEach(result::add);
            return result;
        }

        @Override
        public <S extends CustomerEntity> Optional<S> findOne(Example<S> example) {
            return Optional.empty();
        }

        @Override
        public <S extends CustomerEntity> List<S> findAll(Example<S> example) {
            return List.of();
        }

        @Override
        public <S extends CustomerEntity> List<S> findAll(Example<S> example, Sort sort) {
            return List.of();
        }

        @Override
        public <S extends CustomerEntity> Page<S> findAll(Example<S> example, Pageable pageable) {
            return Page.empty();
        }

        @Override
        public <S extends CustomerEntity> long count(Example<S> example) {
            return 0;
        }

        @Override
        public <S extends CustomerEntity> boolean exists(Example<S> example) {
            return false;
        }

        @Override
        public <S extends CustomerEntity, R> R findBy(Example<S> example, Function<FluentQuery.FetchableFluentQuery<S>, R> queryFunction) {
            return null;
        }

        @Override
        public <S extends CustomerEntity> S save(S entity) {
            return entity;
        }

        @Override
        public <S extends CustomerEntity> List<S> saveAll(Iterable<S> entities) {
            List<S> result = new ArrayList<>();
            entities.forEach(result::add);
            return result;
        }

        @Override
        public Optional<CustomerEntity> findById(String id) {
            return Optional.empty();
        }

        @Override
        public List<CustomerEntity> findAll() {
            return List.of();
        }

        @Override
        public List<CustomerEntity> findAll(Sort sort) {
            return List.of();
        }

        @Override
        public Page<CustomerEntity> findAll(Pageable pageable) {
            return Page.empty();
        }

        @Override
        public List<CustomerEntity> findAllById(Iterable<String> ids) {
            return List.of();
        }

        @Override
        public long count() {
            return 0;
        }

        @Override
        public void deleteById(String id) {}

        @Override
        public void delete(CustomerEntity entity) {}

        @Override
        public void deleteAllById(Iterable<? extends String> ids) {}

        @Override
        public void deleteAll(Iterable<? extends CustomerEntity> entities) {}

        @Override
        public void deleteAll() {}

        @Override
        public boolean existsById(String id) {
            return false;
        }
    }

    @Test
    void testFindByEmail() {
        // Arrange
        CustomerRepository repository = mock(CustomerRepository.class);
        CustomerEntity customer = new CustomerEntity();
        customer.setEmail("test@example.com");
        when(repository.findByEmail("test@example.com")).thenReturn(customer);

        // Act
        CustomerEntity result = repository.findByEmail("test@example.com");

        // Assert
        assertNotNull(result);
        assertEquals("test@example.com", result.getEmail());
        verify(repository).findByEmail("test@example.com");
    }

    @Test
    void testFindByUsername() {
        // Arrange
        CustomerRepository repository = mock(CustomerRepository.class);
        CustomerEntity customer = new CustomerEntity();
        customer.setUsername("testuser");
        when(repository.findByUsername("testuser")).thenReturn(customer);

        // Act
        CustomerEntity result = repository.findByUsername("testuser");

        // Assert
        assertNotNull(result);
        assertEquals("testuser", result.getUsername());
        verify(repository).findByUsername("testuser");
    }

    @Test
    void testSafeFindByEmail() {
        // Arrange
        String testEmail = "test@example.com";
        CustomerRepository repository = new TestCustomerRepository(testEmail);

        // Act
        CustomerEntity result = repository.safeFindByEmail(testEmail);

        // Assert
        assertNotNull(result);
        assertEquals(testEmail, result.getEmail());
    }

    @Test
    void testSafeFindByEmail_WhenCustomerNotFound() {
        // Arrange
        String testEmail = "test@example.com";
        String nonExistentEmail = "nonexistent@example.com";
        CustomerRepository repository = new TestCustomerRepository(testEmail);

        // Act
        CustomerEntity result = repository.safeFindByEmail(nonExistentEmail);

        // Assert
        assertNull(result);
    }

    @Test
    void testFindByResetPasswordToken() {
        // Arrange
        CustomerRepository repository = mock(CustomerRepository.class);
        String token = "reset-token-123";
        CustomerEntity customer = new CustomerEntity();
        customer.setResetPasswordToken(token);
        when(repository.findByResetPasswordToken(token)).thenReturn(customer);

        // Act
        CustomerEntity result = repository.findByResetPasswordToken(token);

        // Assert
        assertNotNull(result);
        assertEquals(token, result.getResetPasswordToken());
        verify(repository).findByResetPasswordToken(token);
    }

    @Test
    void testFindByVerificationToken() {
        // Arrange
        CustomerRepository repository = mock(CustomerRepository.class);
        String token = "verification-token-123";
        CustomerEntity customer = new CustomerEntity();
        customer.setVerificationToken(token);
        when(repository.findByVerificationToken(token)).thenReturn(customer);

        // Act
        CustomerEntity result = repository.findByVerificationToken(token);

        // Assert
        assertNotNull(result);
        assertEquals(token, result.getVerificationToken());
        verify(repository).findByVerificationToken(token);
    }
}